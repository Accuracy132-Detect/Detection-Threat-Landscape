"""Publish only generated research files; verify the SSH host before authentication."""
import argparse
import base64
import hashlib
import hmac
import io
import json
import os
from pathlib import Path
import re
import stat
import uuid

import paramiko

ROOT = '/home/detectm/www'
ASSET = re.compile(r'^research/auto/[a-f0-9]{32}\.(?:pdf|jpg)$')
STATE = 'data/detectra-sync.json'


def fingerprint(key):
    return 'SHA256:' + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip('=')


class PinnedHost(paramiko.MissingHostKeyPolicy):
    def __init__(self, expected):
        self.expected = expected.strip().rstrip('=')

    def missing_host_key(self, client, hostname, key):
        actual = fingerprint(key)
        if not hmac.compare_digest(actual, self.expected):
            raise RuntimeError('SSH host fingerprint mismatch. Server public key (' + key.get_name() + '): ' + actual + '. Authentication and upload stopped; verify with your trusted FileZilla connection.')
        client.get_host_keys().add(hostname, key.get_name(), key)


def remote_bytes(sftp, path):
    try:
        with sftp.open(path, 'rb') as f:
            return f.read()
    except OSError as exc:
        if exc.errno == 2:
            return None
        raise


def mkdir(sftp, path):
    try:
        mode = sftp.lstat(path).st_mode
        if not stat.S_ISDIR(mode):
            raise RuntimeError('Expected a real directory on the server')
    except OSError as exc:
        if exc.errno != 2:
            raise
        sftp.mkdir(path)


def atomic(sftp, destination, content):
    temporary = destination + '.tmp-' + uuid.uuid4().hex
    try:
        sftp.putfo(io.BytesIO(content), temporary, file_size=len(content), confirm=True)
        sftp.chmod(temporary, 0o644)
        # Fail closed on servers without atomic overwrite; never remove live JSON first.
        sftp.posix_rename(temporary, destination)
    finally:
        try:
            sftp.remove(temporary)
        except OSError as exc:
            if exc.errno != 2:
                raise


def validate(source):
    manifest = json.loads((source / 'manifest.json').read_text())
    if not re.fullmatch(r'[a-f0-9]{40}', manifest['commit']):
        raise ValueError('Invalid source revision')
    repository = json.loads((source / 'data/repository.json').read_text())
    studies = json.loads((source / 'data/research.json').read_text())
    if repository['commit'] != manifest['commit'] or not repository['rules'] or not studies:
        raise ValueError('Missing or inconsistent generated collection')
    ids = {r['id'] for r in repository['rules']}
    if len(ids) != len(repository['rules']):
        raise ValueError('Duplicate rule identifiers')
    assets = set(manifest['assets'])
    for name in assets:
        if not ASSET.fullmatch(name) or not (source / name).is_file() or (source / name).is_symlink():
            raise ValueError('Invalid deployment asset')
        if hashlib.sha256((source / name).read_bytes()).hexdigest()[:32] != Path(name).stem:
            raise ValueError('Asset hash mismatch')
    for study in studies:
        if not study['ruleIds'] or not set(study['ruleIds']) <= ids:
            raise ValueError('Research points to a missing rule')
        for field in ('pdf', 'cover'):
            if field in study and study[field].lstrip('/') not in assets:
                raise ValueError('Research points to a missing report or cover')
    allowed = assets | {'data/research.json', 'data/repository.json', 'manifest.json'}
    if any(p.relative_to(source).as_posix() not in allowed for p in source.rglob('*') if p.is_file()):
        raise ValueError('Unexpected file in deployment directory')
    if sum(p.stat().st_size for p in source.rglob('*') if p.is_file()) > 55_000_000:
        raise ValueError('Generated content exceeds storage budget')
    return manifest


def publish(sftp, source, manifest):
    # ROOT and existing data are deliberate fixed destinations, never supplied by research files.
    for directory in (ROOT, ROOT + '/data'):
        if not stat.S_ISDIR(sftp.lstat(directory).st_mode):
            raise RuntimeError('Existing Detectra installation was not found')
    if not sftp.stat(ROOT + '/index.html').st_size:
        raise RuntimeError('Existing Detectra index was not found')
    previous_raw = remote_bytes(sftp, ROOT + '/' + STATE)
    previous = json.loads(previous_raw) if previous_raw else {}
    if previous.get('commit') == manifest['commit']:
        print('This source revision is already published.')
        return
    mkdir(sftp, ROOT + '/research')
    mkdir(sftp, ROOT + '/research/auto')
    # Confirm atomic overwrite support before changing any live data files.
    probe = ROOT + '/data/.detectra-probe-' + uuid.uuid4().hex
    try:
        atomic(sftp, probe, b'first')
        atomic(sftp, probe, b'second')
    finally:
        try:
            sftp.remove(probe)
        except OSError as exc:
            if exc.errno != 2:
                raise
    for name in manifest['assets']:
        payload = (source / name).read_bytes()
        destination = ROOT + '/' + name
        current = remote_bytes(sftp, destination)
        if current != payload:
            atomic(sftp, destination, payload)
    names = ['data/repository.json', 'data/research.json', STATE]
    backup = {name: remote_bytes(sftp, ROOT + '/' + name) for name in names}
    if backup[names[0]] is None or backup[names[1]] is None:
        raise RuntimeError('Existing research indexes are missing; installation needs review')
    state = dict(manifest, previous_assets=previous.get('assets', []))
    content = {name: (source / name).read_bytes() for name in names[:2]}
    content[STATE] = (json.dumps(state, separators=(',', ':')) + '\n').encode()
    changed = []
    try:
        for name in names:
            atomic(sftp, ROOT + '/' + name, content[name])
            changed.append(name)
        for name in names:
            if remote_bytes(sftp, ROOT + '/' + name) != content[name]:
                raise RuntimeError('Remote read-back did not match the generated data')
    except Exception:
        for name in reversed(changed):
            if backup[name] is None:
                sftp.remove(ROOT + '/' + name)
            else:
                atomic(sftp, ROOT + '/' + name, backup[name])
        raise
    # Only remove files recorded by THIS publisher, retaining the previous successful set.
    retain = set(manifest['assets']) | set(previous.get('assets', []))
    obsolete = set(previous.get('previous_assets', [])) - retain
    for name in obsolete:
        if ASSET.fullmatch(name):
            try:
                sftp.remove(ROOT + '/' + name)
            except OSError:
                print('One obsolete generated asset could not be removed; current publication is intact.')
    print(f"Published and verified: {manifest['studies']} studies, {manifest['rules']} rules; revision {manifest['commit'][:12]}.")
    summary = os.environ.get('GITHUB_STEP_SUMMARY')
    if summary:
        with open(summary, 'a') as f:
            f.write(f"## Detectra updated\n\n{manifest['studies']} studies / {manifest['rules']} rules.\n\nRevision: `{manifest['commit']}`.\n\nOpen the site and reload the Research section.\n")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', type=Path, required=True)
    args = parser.parse_args()
    manifest = validate(args.source)
    names = ['OVH_SFTP_HOST', 'OVH_SFTP_USER', 'OVH_SFTP_PASSWORD', 'OVH_SFTP_FINGERPRINT']
    missing = [name for name in names if not os.environ.get(name, '').strip()]
    if missing:
        raise ValueError('Missing GitHub repository secret(s): ' + ', '.join(missing))
    expected = os.environ['OVH_SFTP_FINGERPRINT'].strip()
    if not re.fullmatch(r'SHA256:[A-Za-z0-9+/]{43}=?', expected):
        raise ValueError('OVH_SFTP_FINGERPRINT must be the trusted server SHA256 fingerprint from FileZilla')
    host = os.environ['OVH_SFTP_HOST'].strip()
    if '://' in host or '/' in host or ':' in host:
        raise ValueError('OVH_SFTP_HOST must contain only the server hostname')
    with paramiko.SSHClient() as client:
        client.set_missing_host_key_policy(PinnedHost(expected))
        client.connect(hostname=host, port=22, username=os.environ['OVH_SFTP_USER'],
                       password=os.environ['OVH_SFTP_PASSWORD'], allow_agent=False,
                       look_for_keys=False, timeout=30, auth_timeout=30, banner_timeout=30)
        with client.open_sftp() as sftp:
            sftp.get_channel().settimeout(120)
            publish(sftp, args.source, manifest)


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        # Never dump connection objects or credential-bearing environment values to logs.
        if isinstance(exc, (ValueError, RuntimeError)):
            print('Publication stopped: ' + str(exc))
        else:
            print('Publication stopped: ' + type(exc).__name__ + '. Check the SFTP configuration and server availability.')
        raise SystemExit(1)

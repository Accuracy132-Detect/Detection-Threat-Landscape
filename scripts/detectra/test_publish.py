import errno
import hashlib
import io
import json
from pathlib import Path
import stat
import tempfile
import unittest
from types import SimpleNamespace

from build import mapping
from deploy import ROOT, PinnedHost, fingerprint, publish, validate


class FakeSFTP:
    def __init__(self, fail_index=False):
        self.files = {ROOT+'/index.html': b'original homepage', ROOT+'/assets/site.js': b'original code',
                      ROOT+'/data/repository.json': b'{"old":true}', ROOT+'/data/research.json': b'[]'}
        self.directories = {ROOT, ROOT+'/data'}
        self.fail_index = fail_index
    def lstat(self, path):
        if path in self.directories:
            return SimpleNamespace(st_mode=stat.S_IFDIR, st_size=0)
        if path in self.files:
            return SimpleNamespace(st_mode=stat.S_IFREG, st_size=len(self.files[path]))
        raise OSError(errno.ENOENT, 'missing')
    stat = lstat
    def open(self, path, mode):
        if path not in self.files:
            raise OSError(errno.ENOENT, 'missing')
        return io.BytesIO(self.files[path])
    def mkdir(self, path): self.directories.add(path)
    def putfo(self, stream, path, **kwargs): self.files[path] = stream.read()
    def chmod(self, *args): pass
    def posix_rename(self, source, destination):
        if self.fail_index and destination == ROOT+'/data/research.json':
            self.fail_index = False
            raise RuntimeError('Simulated transfer failure')
        self.files[destination] = self.files.pop(source)
    def remove(self, path):
        if path not in self.files: raise OSError(errno.ENOENT, 'missing')
        del self.files[path]


class PublicationTests(unittest.TestCase):
    def fixture(self, directory):
        root = Path(directory)
        (root/'data').mkdir()
        (root/'research/auto').mkdir(parents=True)
        content = b'%PDF-test'
        asset = 'research/auto/'+hashlib.sha256(content).hexdigest()[:32]+'.pdf'
        (root/asset).write_bytes(content)
        manifest = dict(commit='a'*40, studies=1, rules=1, bytes=8, assets=[asset])
        (root/'manifest.json').write_text(json.dumps(manifest))
        (root/'data/repository.json').write_text(json.dumps(dict(commit='a'*40, rules=[dict(id='rule')])) )
        (root/'data/research.json').write_text(json.dumps([dict(id='study',ruleIds=['rule'],pdf='/'+asset)]))
        return root, manifest
    def test_no_mitre_mapping_is_preserved(self):
        self.assertEqual(mapping('NO-MITRE-MAPPING-test', '// T1059.001')[0], [])
    def test_folder_mapping_has_priority(self):
        self.assertEqual(mapping('T1485-test', '// T1059.001')[0], ['T1485'])
    def test_publish_preserves_application_files_and_is_idempotent(self):
        with tempfile.TemporaryDirectory() as d:
            source, manifest = self.fixture(d)
            validate(source)
            remote = FakeSFTP()
            publish(remote, source, manifest)
            first = dict(remote.files)
            publish(remote, source, manifest)
            self.assertEqual(remote.files, first)
            self.assertEqual(remote.files[ROOT+'/index.html'], b'original homepage')
            self.assertEqual(remote.files[ROOT+'/assets/site.js'], b'original code')
    def test_index_failure_restores_previous_collection(self):
        with tempfile.TemporaryDirectory() as d:
            source, manifest = self.fixture(d)
            remote = FakeSFTP(fail_index=True)
            with self.assertRaises(RuntimeError): publish(remote, source, manifest)
            self.assertEqual(remote.files[ROOT+'/data/repository.json'], b'{"old":true}')
            self.assertEqual(remote.files[ROOT+'/data/research.json'], b'[]')
    def test_missing_asset_stops_validation(self):
        with tempfile.TemporaryDirectory() as d:
            source, manifest = self.fixture(d)
            (source/manifest['assets'][0]).unlink()
            with self.assertRaises(ValueError): validate(source)
    def test_bad_host_key_is_rejected(self):
        key = SimpleNamespace(asbytes=lambda:b'test key', get_name=lambda:'ssh-ed25519')
        client = SimpleNamespace(get_host_keys=lambda:SimpleNamespace(add=lambda *args:None))
        PinnedHost(fingerprint(key)).missing_host_key(client,'host',key)
        with self.assertRaises(RuntimeError):
            PinnedHost('SHA256:wrong').missing_host_key(client,'host',key)


if __name__ == '__main__': unittest.main()

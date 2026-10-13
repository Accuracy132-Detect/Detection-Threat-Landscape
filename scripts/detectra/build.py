"""Export the dated research packages to Detectra's existing static data schema."""
import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path
import re
import subprocess
from urllib.parse import quote

import fitz

DATE_DIR = re.compile(r'^(\d{2}-\d{2}-\d{4}) - (.+)$')
EXTENSIONS = {'.kql': 'Microsoft Defender / Sentinel', '.spl': 'Splunk',
              '.yar': 'YARA', '.yara': 'YARA', '.yaral': 'Google Chronicle / YARA-L',
              '.yara-l': 'Google Chronicle / YARA-L', '.yaml': 'YAML / YARA', '.yml': 'YAML / YARA'}


def mapping(path, header):
    if 'NO-MITRE-MAPPING' in path.upper():
        return [], [], 'Nessun mapping dichiarato'
    pattern = r'\bT\d{4}(?:\.\d{3})?\b'
    ids = sorted(set(re.findall(pattern, path.upper())))
    origin = 'Cartella del pacchetto' if ids else 'Commenti della query'
    ids = ids or sorted(set(re.findall(pattern, header.upper())))
    return ids, sorted(set(re.findall(r'\bTA\d{4}\b', path.upper()))), origin if ids else 'Nessun mapping dichiarato'


def comments(query):
    lines = []
    for line in query.splitlines():
        m = re.match(r'^\s*(?://|#|--|\*)\s?(.*)$', line)
        if m:
            lines.append(m.group(1))
        elif line.strip() and lines:
            break
        elif line.strip() and not lines:
            break
    return '\n'.join(lines)


def asset_bytes(output, payload, suffix):
    name = hashlib.sha256(payload).hexdigest()[:32] + suffix
    destination = output / 'research' / 'auto' / name
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(payload)
    return '/research/auto/' + name


def export(root, output, revision):
    output.mkdir(parents=True, exist_ok=True)
    if any(output.iterdir()):
        raise ValueError('Output directory must be empty')
    tracked = subprocess.check_output(['git', '-C', str(root), 'ls-files', '-z']).decode().split('\0')
    paths = [Path(p) for p in tracked if p and DATE_DIR.match(Path(p).parts[0])]
    for relative in paths:
        if (root / relative).is_symlink() or not (root / relative).resolve().is_relative_to(root.resolve()):
            raise ValueError('Symlink or external path in research package')
    rules, studies = [], []
    repo = 'Accuracy132-Detect/Detection-Threat-Landscape'
    for group in sorted({p.parts[0] for p in paths}):
        date, slug = DATE_DIR.match(group).groups()
        iso = dt.datetime.strptime(date, '%d-%m-%Y').date().isoformat()
        files = sorted(p for p in paths if p.parts[0] == group)
        group_rules = []
        for relative in files:
            if relative.suffix.lower() not in EXTENSIONS:
                continue
            query = (root / relative).read_text(encoding='utf-8-sig')
            if not query.strip():
                raise ValueError(f'Empty rule: {relative}')
            header = comments(query)
            title = next((line for line in header.splitlines() if line.strip() and not re.match(r'(?i)^(MITRE|ATT&CK|Classification|Status|Platform)\b', line)), relative.stem)
            techniques, tactics, origin = mapping(relative.as_posix(), header)
            classification = next((p for p in relative.parts if p in {'hunting', 'validation', 'production-candidates'}), 'Non classificata')
            references = relative.parent / 'references.txt'
            report = relative.parent / 'threat-analysis.pdf'
            rule = dict(id=relative.as_posix(), path=relative.as_posix(), name=title,
                        description=header, query=query, technology=EXTENSIONS[relative.suffix.lower()],
                        techniques=techniques, tactics=tactics, mappingSource=origin,
                        severity='Non dichiarata', validation='Non dichiarata', classification=classification,
                        source='Repository personale', references=(root / references).read_text(encoding='utf-8-sig') if references in files else '',
                        url=f'https://github.com/{repo}/blob/{revision}/' + quote(relative.as_posix(), safe='/'))
            if report in files:
                rule['report'] = report.as_posix()
            group_rules.append(rule)
        if not group_rules:
            continue
        reports = [root / p for p in files if p.name == 'threat-analysis.pdf']
        pdf_url = cover_url = None
        if reports:
            # Keep every report in a multi-rule study, in repository path order.
            with fitz.open() as merged:
                seen = set()
                for pdf in reports:
                    content = pdf.read_bytes()
                    digest = hashlib.sha256(content).hexdigest()
                    if digest in seen:
                        continue
                    seen.add(digest)
                    with fitz.open(stream=content, filetype='pdf') as document:
                        if document.needs_pass or document.page_count == 0:
                            raise ValueError(f'Unreadable report: {pdf}')
                        merged.insert_pdf(document)
                data = reports[0].read_bytes() if len(seen) == 1 else merged.tobytes(garbage=4, deflate=True, no_new_id=True)
                pdf_url = asset_bytes(output, data, '.pdf')
                page = merged[0]
                pix = page.get_pixmap(matrix=fitz.Matrix(900 / page.rect.width, 900 / page.rect.width), alpha=False)
                cover_url = asset_bytes(output, pix.tobytes('jpeg', jpg_quality=80), '.jpg')
        study = dict(id=group, title=slug.replace('-', ' ').capitalize(), date=date, dateISO=iso,
                     summary=group_rules[0]['name'], ruleIds=[r['id'] for r in group_rules],
                     platforms=sorted({r['technology'] for r in group_rules}),
                     techniques=sorted({t for r in group_rules for t in r['techniques']}))
        if pdf_url:
            study.update(pdf=pdf_url, cover=cover_url)
        studies.append(study)
        rules.extend(group_rules)
    if not studies or not rules:
        raise ValueError('Empty export; refusing to replace the online collection')
    studies.sort(key=lambda s: (s['dateISO'], s['id']), reverse=True)
    (output / 'data').mkdir(exist_ok=True)
    def write(name, value):
        (output / 'data' / name).write_text(json.dumps(value, ensure_ascii=False, separators=(',', ':')) + '\n')
    write('repository.json', dict(branch='threat-landscape', commit=revision,
                                  fetchedAt=dt.datetime.now(dt.timezone.utc).date().isoformat(), rules=rules))
    write('research.json', studies)
    total = sum(p.stat().st_size for p in output.rglob('*') if p.is_file())
    if total > 55_000_000:
        raise ValueError('Export exceeds the 55 MB budget; review OVH capacity before publishing')
    manifest = dict(commit=revision, rules=len(rules), studies=len(studies), bytes=total,
                    assets=sorted(p.relative_to(output).as_posix() for p in (output / 'research').rglob('*') if p.is_file()))
    (output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(f'Validated export: {len(studies)} studies, {len(rules)} rules, {total / 1e6:.2f} MB')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', type=Path, default=Path('.'))
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    revision = subprocess.check_output(['git', '-C', str(args.root), 'rev-parse', 'HEAD'], text=True).strip()
    export(args.root.resolve(), args.output.resolve(), revision)

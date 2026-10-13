# Detectra research → OVH

The workflow `.github/workflows/detectra-ovh.yml` runs after pushes to
`threat-landscape` and can be started from **Actions → Update Detectra research
on OVH → Run workflow**. It reads the latest branch tip to avoid an older queued
run overwriting a newer publication. Jobs are serialized.

## Repository secrets

- `OVH_SFTP_HOST`: bare server hostname, no scheme or port.
- `OVH_SFTP_USER`: existing OVH SFTP account.
- `OVH_SFTP_PASSWORD`: the SFTP password.
- `OVH_SFTP_FINGERPRINT`: the trusted server host-key fingerprint shown by
  FileZilla, in `SHA256:...` form. Verify against the existing trusted connection
  or OVH support, not an unverified scan. This is the server's public identity,
  not a password or private key. It is checked before password authentication.

The destination is fixed at `/home/detectm/www`, port 22. The site must already
be installed. No secrets or passwords belong in repository files.

## Published content

The exporter reads tracked files only inside `DD-MM-YYYY - threat-name/`
packages. It includes KQL, SPL, YARA/YARA-L and YAML query files, adjacent
`references.txt`, and `threat-analysis.pdf` reports. Each dated package becomes
a research card. All reports in a multi-report package are combined for the
embedded study PDF; original reports remain linked from each query.
The cover is rendered from the first page. Titles derive from the package name,
summaries from the existing query header; no AI text or invented findings are added.

Generated JSON matches the existing Detectra frontend. A query's classification
is not treated as production validation. `NO-MITRE-MAPPING` stays unmapped.
Tactics are resolved by the site's existing ATT&CK catalogue; this workflow does
not update ATT&CK itself.

Only `data/repository.json`, `data/research.json`, `data/detectra-sync.json`, and
content-addressed assets under `research/auto/` are published. Application code,
profile, contacts, homepage, configuration and older manually uploaded files are
not managed here. The publisher retains the preceding successful asset set and
only removes obsolete files from its own manifest.

Assets are uploaded first. JSON files are replaced individually via the SFTP
POSIX atomic rename extension, with read-back checks and rollback on caught
publication errors. The two JSON files are NOT one atomic transaction: a visitor
loading during the short switch can temporarily see different revisions. An
abrupt runner termination can interrupt rollback; rerun the workflow to converge.
Browser caches or an already-open tab may need a refresh.

The export stops above 55 MB. It does not determine the OVH account's remaining
quota; uploads fail without switching the indexes if the server runs out of
space. Review storage growth periodically on the 100 MB hosting plan.

## First activation and diagnostics

1. Set all four repository secrets.
2. Open Actions and run the workflow on `threat-landscape`.
3. Confirm the `Publish research to OVH` step succeeds; reload the Research page.

The run summary gives the source revision, number of studies and rule count.
A fingerprint mismatch blocks authentication; never disable host verification
to resolve it. Check the trusted fingerprint/host-key algorithm instead.

A push made by a separate workflow using GitHub's own `GITHUB_TOKEN` normally
will not start another push workflow. Such a producer must explicitly dispatch
this workflow or invoke its publication steps. External user/app pushes use the
normal push trigger.

## Local checks

```sh
python -m pip install -r scripts/detectra/requirements.txt
python -m unittest discover -s scripts/detectra -p 'test_*.py'
python scripts/detectra/build.py --output /absolute/path/to/empty-output
```

The build reads queries as text; it never executes detection queries or package
scripts. The deployment step consumes only the generated output and fixed paths.

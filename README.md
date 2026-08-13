# Generated website output

This public repository is reserved for reviewed, generated website files. The
private Hugo source and editorial workspace are maintained separately. The
intended canonical address is `https://xinyujiajoseph.co.uk/`. Custom domain
activation is managed separately from the release workflow.

## Release contract

Each release contains two items at the repository root:

1. `site/`, containing the complete static website.
2. `PROVENANCE.json`, containing exactly the following fields.

```json
{
  "schema_version": 1,
  "source_repository": "xinuum/personal-website",
  "source_commit": "40 lowercase hexadecimal characters",
  "hugo_version": "0.165.0",
  "site_tree_sha256": "64 lowercase hexadecimal characters"
}
```

The tree digest covers every regular file under `site/`. Files are ordered by
their UTF 8 encoded POSIX relative path. For each file, the digest receives the
eight byte big endian path length, the path bytes, the eight byte big endian
content length, and the file bytes.

The workflow audits every pull request to `main`. A push to protected `main` is
audited again, packaged from `site/`, and passed to GitHub Pages through its
OIDC deployment flow. Pull request runs never package or deploy the site.

## Local verification

The self test creates temporary positive and negative fixtures. It does not
need a real website release.

```sh
./scripts/test-audit-public-output.sh
```

Run the release audit before committing generated output:

```sh
./scripts/audit-public-output.sh
```

Calculate the digest for a prepared site directory with:

```sh
python3 scripts/public_output_audit.py tree-hash site
```

The audit rejects source trees, drafts, preview templates, credential shaped
values, known private legacy content, symbolic links, executable files, hidden
files, unreviewable document archives, and image metadata that may expose
private information. Generated AVIF images are accepted after container, type,
dimension and metadata checks. PDF publication requires a future reviewed
metadata policy before that format can enter `site/`.

Copyright © 2026 Xinyu (Joseph) Jia. All rights reserved.

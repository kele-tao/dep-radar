# SBOM: the schema subset dep-radar emits

`dep-radar sbom` produces JSON in two dialects. Both are *like* the real standards
rather than certified conformant documents: they use the same field names and structure
for the subset below, which is what a consumer needs to ingest components, licences,
identifiers and hashes. `--validate` checks exactly this subset, and the tests assert the
same invariants.

## CycloneDX-like (`--format cyclonedx`)

| Field | Always present | Meaning |
| --- | :---: | --- |
| `bomFormat` | yes | `"CycloneDX"` |
| `specVersion` | yes | `"1.5"` |
| `serialNumber` | yes | `urn:uuid:`, uuid5 over the absolute project path (stable across runs) |
| `version` | yes | `1` |
| `metadata.timestamp` | yes | `SOURCE_DATE_EPOCH` if set, else `2026-01-01T00:00:00Z` |
| `metadata.tools[0]` | yes | vendor, name, version of dep-radar |
| `metadata.component` | yes | the scanned project, `type: application` |
| `components[].type` | yes | always `library` |
| `components[].bom-ref` | yes | unique purl, suffixed with `#2` etc. for duplicate copies |
| `components[].name` | yes | package name |
| `components[].version` | when known | resolved version |
| `components[].purl` | yes | `pkg:npm/...` or `pkg:pypi/...` |
| `components[].scope` | yes | `required`, `optional` or `excluded` (dev) |
| `components[].licenses` | yes | `[{license: {id}}] or `NOASSERTION` |
| `components[].hashes` | when the lockfile has `integrity` | `SHA-512` etc., value is the SRI base64 payload |
| `components[].externalReferences` | non-registry sources only | the git/tarball URL |
| `dependencies[]` | yes | `{ref, dependsOn}`, root plus one entry per component with children |

## SPDX-like (`--format spdx`)

| Field | Always present | Meaning |
| --- | :---: | --- |
| `spdxVersion` | yes | `"SPDX-2.3"` |
| `dataLicense` | yes | `"CC0-1.0"` |
| `SPDXID` | yes | `"SPDXRef-DOCUMENT"` |
| `name` | yes | `<project>-sbom` |
| `documentNamespace` | yes | deterministic URI derived from the project path |
| `creationInfo.created` | yes | same deterministic timestamp as above |
| `creationInfo.creators` | yes | `Tool: dep-radar-<version>` |
| `packages[0]` | yes | the project itself, `SPDXRef-RootPackage` |
| `packages[].SPDXID` | yes | `SPDXRef-Package-<n>`, stable ordering by name |
| `packages[].versionInfo` | yes | version or `NOASSERTION` |
| `packages[].downloadLocation` | yes | resolved URL, or `NOASSERTION` |
| `packages[].licenseDeclared` | yes | declared licence id, or `NOASSERTION` |
| `packages[].externalRefs[0]` | yes | package-manager purl |
| `packages[].checksums` | when available | `SHA512` etc. from lockfile integrity |
| `relationships[]` | yes | `DEPENDS_ON` from the root to every package |

## Known differences from the real schemas

- CycloneDX requires `component.hashes` to reference actual artefact hashes; the SRI
  payload from a lockfile is an artefact hash, but dep-radar does not decode it to hex.
- SPDX requires a licence list document and richer `creationInfo`; both are omitted.
- No `bom-ref`/`SPDXID` cross-document linking, no signing, no `vulnerabilities` section.

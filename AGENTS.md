# Repository agent instructions

Read CONTEXT.md and the relevant docs/adr decision before changing collector behavior.
README.md is the current public install and operator contract.

- Keep investigated files, ACLs, reparse points, attributes and system policy read-only.
- Keep observations, collection failures, bounded hypotheses and UNKNOWN separate.
- Static evidence and exit 0 never prove runtime enforcement or safety.
- Use synthetic local fixtures; keep incident data, credentials, paths and identities out of public issues and commits.
- Preserve the native API/access/body review gate and resource bounds; a body digest alone is not a safety proof.
- Scope a change to the requested contract; preserve unrelated edits and failed evidence.
- Report actual source identity, executed checks and remaining limitations separately.
- Follow SECURITY.md for vulnerability disclosure and CONTRIBUTING.md for changes.

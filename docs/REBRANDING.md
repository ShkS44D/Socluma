# Socluma rename and existing installations

The project is now **Socluma — AI-Assisted Security Operations**, a personal cybersecurity engineering project. The repository is https://github.com/ShkS44D/Socluma.

## Data and credentials

- No database, Docker volume, collector spool, credential file, or generated report is deleted by this rename.
- A new local SQLite installation uses `socluma.db`. If that file does not exist and `vigilantai.db` exists in the working directory, the application continues using the existing database. `DATABASE_URL_OVERRIDE` takes precedence. If both files exist, the new filename takes precedence; use an explicit override to select the other file.
- Existing PostgreSQL database names, roles, and passwords are infrastructure identifiers. Keep their existing values when reusing a database volume. The development Compose defaults retain the original identifiers and signing secrets for compatibility; they can be overridden using environment variables. New production deployments should supply their own database names and strong secrets.
- Keep signing and encryption keys unchanged during the rename. Changing keys can invalidate sessions, collector tokens, and encrypted provider credentials.
- JWT issuer defaults and the Redis AI idempotency-lock namespace retain the previous protocol identifiers so existing tokens validate and mixed-version workers coordinate the same requests. These are deliberately separate from display branding.
- Browser access/refresh tokens and theme preferences migrate from their previous keys to the `socluma` keys. Logout removes both generations of credentials.
- The MFA issuer defaults to Socluma. The previous issuer remains accepted for existing configurations; enrolled authenticator entries may retain their original label.
- In existing untracked environment files, set `PROJECT_NAME=Socluma` and `MFA_ISSUER=Socluma`. Preserve all credentials and database connection values.

## Integrations and deployment

- The collector service template is now `collector-agent/install/socluma-collector.service`. Existing services and their state directories should be migrated deliberately rather than deleted.
- Linux installation overrides now use `SOCLUMA_INSTALL_DIR` and `SOCLUMA_STATE_DIR`; existing directories can be selected with those variables.
- Celery's application label, metric prefixes, export filenames, and deterministic AI model label now use Socluma. Update external monitoring queries or scripts that depend on the previous names. Stored historical records are not rewritten.
- The local checkout directory does not need to be renamed. Documentation uses `D:\Socluma` as an example; substitute the actual checkout path.

## Repository cleanup

Removed the empty root `package-lock.json` (there is no root Node.js package), four empty, unreferenced component index files under `admin`, `alerts`, `auth`, and `common`, and the empty, unreferenced pages index. The frontend retains its actual package lockfile. The obsolete MVP roadmap was deleted rather than retained in an archive.

Database migrations, fixtures, tests, operational guides, validation history, and generated user documents are retained.

## Rename validation - 17 October 2026

- Focused backend regression checks: 29 passed, covering database selection, branding compatibility, AI provider behavior, incident validation, Sigma rules, IOC extraction, production configuration validation, and telemetry text formats.
- Collector tests: 14 passed.
- Browser-storage unit tests: 5 passed, including previous-key migration, refresh-token preservation, logout, and theme preservation.
- Frontend lint, TypeScript compilation, and production build passed.
- Backend and collector Python compilation passed. Alembic reports the single existing head `20260801_2000`.
- Development, acceptance, and production Compose configuration checks passed. Acceptance and production interpolation used temporary validation values, not saved credentials.
- Backend validation disabled external AI and threat-intelligence providers for the test process. The full 238-test backend suite was interrupted before completion; it is not reported as passed.
- Docker was not running, so live container, browser end-to-end, and PostgreSQL runtime checks were not performed for this rename.
- The initial rename removed five unused tracked files. A subsequent cleanup deleted the obsolete MVP roadmap and the empty pages index instead of retaining archived scaffolding.
- Local credentials, databases, collector state, and generated PDFs are excluded from the commit. GitHub repository visibility is preserved as public.

## Follow-up deletion cleanup

The obsolete `docs/archive/MVP_ARCHITECTURE.md` and empty, unreferenced `frontend/src/pages/index.ts` are deleted from the working tree and current repository rather than retained as archived files. Existing Git commits still contain earlier revisions; this cleanup does not rewrite repository history.

Eight stale test databases under `tmp/`, five generated cache or temporary-test directories, and the resulting empty directories were verified as cleanup candidates. Automatic approval review blocked the shell deletion command, so these ignored local artifacts remain. Active application databases, credentials, dependencies, generated documents, and their authoring sources are retained.

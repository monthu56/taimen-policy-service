# Contributing to Taimen Policy Service

Thank you for taking the time to contribute. Taimen is an organizational
runtime in which people, AI agents, workflows and services execute the work
of an organization; the platform is developed in the open under the
Apache License 2.0.

This repository holds one component of the platform: the Policy Service, the
Policy Decision Point (ReBAC authorization over OpenFGA). The umbrella
repository, [monthu56/taimen](https://github.com/monthu56/taimen), includes
it as a git submodule and holds the platform-wide documents referenced below.

## Before you start

- Read the [Product Vision](https://github.com/monthu56/taimen/blob/main/docs/product-vision.md)
  and the [ADR registry](https://github.com/monthu56/taimen/blob/main/docs/adr/README.md).
  Architecture decisions are recorded as ADRs (in Russian, with an English
  title line); English summaries are provided on request in the ADR's
  discussion.
- This component has no ADR series of its own. The decisions behind it live in
  the umbrella registry — primarily
  [TAI-ADR-0025](https://github.com/monthu56/taimen/blob/main/docs/adr/ADR-0025-authorization-model-and-policy-service.md)
  (authorization model and policy service) — and in the design note
  [`docs/policy-service/design-v0.md`](https://github.com/monthu56/taimen/blob/main/docs/policy-service/design-v0.md).
- Check the [roadmap](https://github.com/monthu56/taimen/blob/main/docs/roadmap.md)
  and open issues before starting a large change. For anything that changes
  an API, a data model or a service boundary, open an issue first and propose
  an ADR in the umbrella repository.

## Contributor License Agreement

We require a signed Contributor License Agreement (CLA) for every
contribution, so that the project can be relicensed or defended without
tracking down every author. The CLA is checked by cla-assistant on each pull
request; you sign once.

- Individuals: [`cla/CLA-individual.md`](https://github.com/monthu56/taimen/blob/main/cla/CLA-individual.md)
- Companies contributing on behalf of employees: [`cla/CLA-entity.md`](https://github.com/monthu56/taimen/blob/main/cla/CLA-entity.md)

The CLA grants the project a copyright and patent licence to your
contribution; you keep your copyright.

## Development setup

The component is a Python 3.12 project (see `.python-version`) managed with
[uv](https://docs.astral.sh/uv/). It depends on `platform-auth-sdk` by path
(`../platform-auth-sdk`, declared in `[tool.uv.sources]` of `pyproject.toml`),
so either work from the umbrella checkout, where the SDK is a sibling
submodule, or keep a checkout of `platform-auth-sdk` next to this repository.

```bash
uv sync                                  # runtime dependencies + the `dev` group (pytest, ruff, aiosqlite, pyjwt)
uv run ruff check . && uv run ruff format --check .
uv run pytest -q                         # unit tests; a temporary SQLite database, no services needed
```

End-to-end tests (`tests/test_api.py`, `tests/test_projection.py`, marker
`fga`) need a live OpenFGA. They are skipped when nothing answers at
`POL_TEST_FGA_URL` (default `http://127.0.0.1:18090`); `compose.test.yml`
starts an in-memory OpenFGA on that port:

```bash
docker compose -f compose.test.yml up -d --wait openfga
POL_TEST_FGA_URL=http://127.0.0.1:18090 uv run pytest -q
docker compose -f compose.test.yml down
```

This is what `make test-policy-service` in the umbrella does; `make
check-policy-service` adds the ruff checks.

The service itself keeps its state in PostgreSQL (`POL_DATABASE_URL`, schema
managed by Alembic: `uv run alembic upgrade head`) and needs an OpenFGA
instance (`POL_FGA_URL`). Tests do not need PostgreSQL. To run the service
locally, copy `.env.example` to `.env` and adjust the `POL_*` settings
(documented in `src/policy_service/config.py`), then start the API with
`uv run policy-service` (port 8030) and the projection worker with
`uv run policy-worker`. The simplest way to get PostgreSQL, OpenFGA and the
service together is the umbrella's `policy` compose profile:
`make up PROFILES="core edge policy"` from the umbrella checkout.

The Docker image is built from the umbrella root, because the build context
must contain the SDK next to the service:
`docker build -f policy-service/Dockerfile .`.

## Pull requests

- One logical change per pull request; keep the history linear (rebase, no
  merge commits).
- Tests and `ruff check` / `ruff format --check` must pass; behaviour changes
  come with tests.
- Commit messages explain *why*, not *what*; reference the ADR or issue.
- Public API changes (routes, schemas, env variables) update the component's
  docs and, when they break compatibility, the umbrella's
  `docs/migration-vX.Y.md`.
- The pull request template asks you to confirm the CLA and that no secrets,
  customer data or internal hostnames are included.

## Reporting bugs and security issues

Bugs: open an issue in this repository with the version, steps to reproduce
and logs. Security issues: see [SECURITY.md](SECURITY.md) and do not open a
public issue.

## Code of conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md).

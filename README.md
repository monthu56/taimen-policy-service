# policy-service

*English. Русская версия: [README.ru.md](README.ru.md)*

Platform Policy Decision Point (TAI-ADR-0025): ReBAC authorization over OpenFGA.
Design of the first slice — [`docs/policy-service/design-v0.md`](https://github.com/taimen-ai/taimen/blob/main/docs/policy-service/design-v0.md)
in the umbrella repository.

This component ships as the optional experimental `policy` profile of the open build
([ADR-0040](https://github.com/taimen-ai/taimen/blob/main/docs/adr/ADR-0040-open-source-delivery-and-experimental-profiles.md)
of the umbrella) and is not part of the `core` profile.

- `src/policy_service/catalog.py` — parsing of the resource servers' `authz/catalog.yaml`;
- `model_builder.py` — building the OpenFGA model from the catalogs;
- `core.py` — per-tenant stores, roles, bindings, delegations, decisions, projection;
- `app.py` — HTTP API (decisions, admin), `worker.py` — projection worker over the
  Control Plane and IAM event journals;
- `tools/spike_fga.py` — model and latency spike.

Tests: `uv run pytest` (the end-to-end tests require a live OpenFGA,
`POL_TEST_FGA_URL`, default `http://127.0.0.1:18090`; without it they are
skipped):

```bash
docker run -d --name fga-spike -p 127.0.0.1:18090:8080 openfga/openfga:latest run
```

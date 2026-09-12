# policy-service

Policy Decision Point платформы (TAI-ADR-0025): ReBAC-авторизация над OpenFGA.
Дизайн первого среза — `docs/policy-service/design-v0.md` суперпроекта.

- `src/policy_service/catalog.py` — разбор `authz/catalog.yaml` resource servers;
- `model_builder.py` — сборка модели OpenFGA из каталогов;
- `core.py` — stores per tenant, роли, bindings, делегации, решения, проекция;
- `app.py` — HTTP API (decisions, admin), `worker.py` — воркер проекции журналов
  Control Plane и IAM;
- `tools/spike_fga.py` — спайк модели и латентности.

Тесты: `uv run pytest` (сквозные тесты требуют живой OpenFGA,
`POL_TEST_FGA_URL`, по умолчанию `http://127.0.0.1:18090`; без него они
пропускаются):

```bash
docker run -d --name fga-spike -p 127.0.0.1:18090:8080 openfga/openfga:latest run
```

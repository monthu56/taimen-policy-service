-- Вторая база в том же PostgreSQL для datastore OpenFGA (compose-профиль policy).
-- Схему в ней создаёт одноразовый контейнер `openfga-migrate`.
CREATE DATABASE openfga;
GRANT ALL PRIVILEGES ON DATABASE openfga TO policy;

# vps_probe stack (postgres + grafana)

Runs on the hub (中控机, e.g. `43.164.2.59`) via `docker compose`.

## Layout

```
docker/
├── docker-compose.yml
├── .env                       # secrets (POSTGRES_PASSWORD, GRAFANA_ADMIN_PASSWORD)
├── stack.sh                   # helper: up / down / logs / psql / ps
├── postgres/
│   └── initdb/
│       └── 01_schema.sql      # tables + views (runs once on empty PGDATA)
└── grafana/
    ├── provisioning/
    │   ├── datasources/postgres.yaml
    │   └── dashboards/dashboards.yaml
    └── dashboards/            # dashboard JSON (task 3)
```

## Endpoints

| service  | listen              | notes                                |
|----------|---------------------|--------------------------------------|
| postgres | `127.0.0.1:25432`   | local only, credential in `.env`     |
| grafana  | `[::]:33000`        | v4 + v6, admin creds in `.env`       |

## Data

Named volumes (managed by Docker):
- `probe_pg_data`       — postgres `PGDATA`
- `probe_grafana_data`  — grafana db + plugins

To wipe cleanly and re-init the schema:

```
./stack.sh down
docker volume rm probe_pg_data
./stack.sh up
```

## First-time setup on the hub

```
scp -r docker/ root@<hub>:/root/vps_probe/
ssh root@<hub> 'cd /root/vps_probe/docker && ./stack.sh up'
```

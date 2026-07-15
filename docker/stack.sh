#!/usr/bin/env bash
# thin wrapper for docker compose stack in this dir
set -euo pipefail

cd "$(dirname "$0")"

cmd="${1:-help}"
shift || true

case "$cmd" in
  up)      docker compose up -d "$@" ;;
  down)    docker compose down "$@" ;;
  restart) docker compose restart "$@" ;;
  logs)    docker compose logs -f --tail=200 "$@" ;;
  ps)      docker compose ps ;;
  psql)    docker compose exec -it postgres \
             psql -U "$(grep '^POSTGRES_USER=' .env | cut -d= -f2)" \
                  -d "$(grep '^POSTGRES_DB=' .env | cut -d= -f2)" "$@" ;;
  pull)    docker compose pull ;;
  help|*)
    cat <<EOF
usage: $0 <cmd>

  up       start stack (detached)
  down     stop and remove containers (volumes kept)
  restart  restart all services
  logs     tail logs
  ps       show status
  psql     open psql shell inside pg container
  pull     pull latest images
EOF
    ;;
esac

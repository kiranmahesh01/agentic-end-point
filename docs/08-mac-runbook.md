# Mac runbook (this laptop)

Tested 20 August 2026 on Palbars-MBP-7 (Apple silicon) with Homebrew Docker + Colima. Docker Desktop was **not** installed.

## Prerequisites

```bash
brew install docker docker-compose colima
mkdir -p ~/.docker/cli-plugins
ln -sf "$(brew --prefix docker-compose)/libexec/docker/cli-plugins/docker-compose" \
  ~/.docker/cli-plugins/docker-compose
# if that path 404s:
ln -sf /opt/homebrew/Cellar/docker-compose/*/lib/docker/cli-plugins/docker-compose \
  ~/.docker/cli-plugins/docker-compose
colima start --cpu 4 --memory 6
docker context use colima
docker compose version   # must print a version, not "unknown command"
```

If `colima start` fails with a SHA512 mismatch, delete the cache and retry:

```bash
rm -rf ~/Library/Caches/colima/caches
colima start
```

## Start

```bash
cd ~/agentic-end-point
make up
make health
make demo
```

`make health` should print OK for every service. Then open:

- Homepage: http://127.0.0.1:8080/
- API docs: http://127.0.0.1:8080/docs
- Demo agent: http://127.0.0.1:8090/docs
- Kill switch: http://127.0.0.1:8086/docs

`http://localhost:8080/` with no path used to 404. That is not “the server is down.” Use `/` after the homepage patch, or `/docs`.

## Stop

```bash
make down
# optional: colima stop
```

## Ports

| Port | Service |
|---|---|
| 8080 | Broker / homepage |
| 8081 | Registry |
| 8082 | PDP load balancer |
| 8083 | Identity |
| 8084 | Approval |
| 8085 | Telemetry |
| 8086 | Kill switch |
| 8087 | Egress proxy |
| 8088 | EDR sensor |
| 8089 | Isolated desktop |
| 8090 | Demo agent |
| 8443 | Local IdP |
| 6379 | Redis |

## If `make up` fails

1. `docker info` — daemon must be up (`colima start`).
2. `docker compose version` — plugin must be linked.
3. Image build `OSError: Readme file does not exist` — Dockerfiles must `COPY README.md` and `COPY LICENSE`.
4. Service `unhealthy` while logs show Uvicorn running — healthcheck is using missing `curl`. Python healthchecks are in `docker-compose.yml`.
5. PDP LB unhealthy, PDPs themselves healthy — nginx healthcheck must hit `http://127.0.0.1/health`, not `localhost`.

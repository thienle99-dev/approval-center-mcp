# Docker deployment

Create or identify the private Docker bridge shared with GoClaw. Set `GOCLAW_DOCKER_NETWORK` to its exact name. `docker-compose.yml` publishes no host port and only exposes port 8080 to that network. Telegram long polling needs outbound HTTPS from the container.

```sh
docker network create goclaw-net
cp .env.example .env
cp config/policies.example.yaml config/policies.yaml
chmod 600 .env
# Replace every placeholder with high-entropy values before launch.
docker compose build
docker compose up -d
docker compose ps
docker compose logs --tail=100 approval-center-mcp
```

Use Docker secrets in production by mounting secret files and setting `AGENT_TOKEN_FILE`, `ADMIN_TOKEN_FILE`, and `TELEGRAM_BOT_TOKEN_FILE` to their paths. The service reads those paths when the corresponding environment value is absent. Do not commit the secret files.

The container runs as UID 10001, drops Linux capabilities, uses a read-only root filesystem and a writable persistent `/data` volume. Compose caps memory at 256 MiB and CPU at 0.5. Those are limits, not measured consumption. Load-test on the target VPS and inspect `docker stats` before claiming the resource goals.

To back up, stop the container and copy the persistent volume with correct ownership, or use SQLite online backup. Restore the backup while the service is stopped, then start and verify `/readyz` and audit state.

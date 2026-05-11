# K3 Lens Docker cleanup policy

K3 Lens runs Hermes/Multica services on a Docker-backed droplet. Docker images and
BuildKit cache are allowed to grow during image builds, but cleanup should stay
explicitly scoped to disposable Docker artifacts.

## Trigger

Run Docker cleanup when the root filesystem has **less than 25% free space**.

Check manually:

```bash
df -h /
docker system df
```

The guarded script in `scripts/ops/k3-lens-docker-cleanup.sh` uses the same
threshold by default:

```bash
sudo FREE_THRESHOLD_PCT=25 /usr/local/sbin/k3-lens-docker-cleanup --dry-run
sudo FREE_THRESHOLD_PCT=25 /usr/local/sbin/k3-lens-docker-cleanup
```

Use `--force` only for an operator-approved maintenance run when free space is
not yet below the threshold.

## Allowed cleanup scope

The approved cleanup commands are:

```bash
docker builder prune -af --keep-storage 8GB
docker image prune -af
```

Rationale:

- `docker builder prune` removes unused BuildKit/build cache.
- `docker image prune -a` removes images not used by any existing container,
  including old local build tags such as stale `k3-lens-hermes:kca43-*` tags.
- Running containers keep their images pinned, so currently deployed containers
  are not removed by these commands.

## Never prune automatically

Do **not** run these as part of this policy:

```bash
docker system prune --volumes
docker volume prune
docker container prune
rm -rf /srv/k3-lens
rm -rf /srv/k3-lens/data
rm -rf ~/.hermes
```

Never delete named volumes, database data, backups, secrets, mounted application
state, or `/srv/k3-lens` data directories during Docker cache cleanup.

## Guarded systemd timer

The droplet can run the guarded cleanup script from a timer. Suggested units:

`/etc/systemd/system/k3-lens-docker-cleanup.service`

```ini
[Unit]
Description=K3 Lens guarded Docker image/build-cache cleanup
Requires=docker.service
After=docker.service

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/k3-lens-docker-cleanup
```

`/etc/systemd/system/k3-lens-docker-cleanup.timer`

```ini
[Unit]
Description=Check K3 Lens Docker disk cleanup threshold hourly

[Timer]
OnBootSec=10m
OnUnitActiveSec=1h
Persistent=true

[Install]
WantedBy=timers.target
```

Enable:

```bash
sudo install -m 0755 scripts/ops/k3-lens-docker-cleanup.sh /usr/local/sbin/k3-lens-docker-cleanup
sudo systemctl daemon-reload
sudo systemctl enable --now k3-lens-docker-cleanup.timer
```

## Verification

Before and after any cleanup, capture:

```bash
df -h /
docker system df
journalctl -u k3-lens-docker-cleanup.service -n 100 --no-pager
sudo tail -n 100 /var/log/k3-lens-docker-cleanup.log
```

A healthy no-op run above the threshold logs a `skip` line and performs no
cleanup.

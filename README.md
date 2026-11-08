# DiskHog 🐗

What is eating disk on your Debian VMs, in one page. Local only — no cloud, no account, no telemetry. Stdlib-only Python, no pip packages, no CDN JS.

## What it surfaces

- **Overview** — every filesystem, used / free / %, with a bar.
- **Largest folders** — click any folder to drill down into its children.
- **Largest files** — top 200, filterable, with modified date.
- **Categories** — the usual suspects, summed: Docker images/layers, Docker container logs, Docker volumes, system logs, APT cache, Python installs, pip cache, `/tmp`, home caches.
- **Docker** — from the Docker API (`docker system df`): images with size / dangling / unused, containers, volumes, build cache. Unused = no container references the image.
- **Python versions** — every `python3.x` tree in `/usr/lib`, `/usr/local/lib`, `/opt`, and `~/.pyenv/versions`, with the current version marked. **Distro python in `/usr/lib` is flagged DO NOT DELETE** — apt and the OS use it. Only pyenv / `/usr/local` / `/opt` versions are offered for removal, and only if they aren't the current one.
- **Logs** — every big `*.log`, plus the systemd journal size.

Every finding also shows the exact shell command to fix it by hand, so you never have to trust the buttons.

## Run it

### In Docker (recommended — one per host)

`docker-compose.yml` pulls the prebuilt image that CI publishes to GHCR on every push to main (`ghcr.io/pete1450/disk-hog:latest`). No build needed on the host:

```bash
docker compose up -d
# open http://<host-lan-ip>:8081
```

To pick up a new release later: `docker compose pull && docker compose up -d` (the compose file already sets `pull_policy: always`, so a plain `up -d` pulls the latest image too).

It mounts `/:/host` and `/var/run/docker.sock:ro`. See `docker-compose.yml` for why, and for the read-only variant (`:ro` + `ENABLE_CLEANUP=0`).

### Building the image yourself

If you'd rather build locally than pull the GHCR image — for dev, or to test a change before pushing — use the dev override, which builds the `Dockerfile` in this repo and tags it `diskhog:local`:

```bash
docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d --build
# open http://<host-lan-ip>:8081
```

Or just the image, without Compose:

```bash
docker build -t diskhog:local .
docker run -d --name diskhog -p 8081:8081 \
  -e HOST_ROOT=/host -e ENABLE_CLEANUP=1 \
  -v /:/host:rw -v /var/run/docker.sock:/var/run/docker.sock:ro \
  diskhog:local
```

### Directly on the host

```bash
python3 app.py
# open http://localhost:8081
```

This is the only mode where **apt clean** and **journal vacuum** buttons work — inside the container those buttons give you the host command instead, because the container's apt/journal aren't the host's.

## Exclusions

Some paths should never be scanned — a big network mount under `/mnt`, a backup drive, anything you already know about. Set them in `docker-compose.yml` (or `EXCLUDE_PATHS` when running directly):

```yaml
- EXCLUDE_PATHS=/mnt,/media,/srv/backups
```

Comma-separated, absolute paths. An excluded path is never walked, counted, or shown — not in largest folders/files, not in categories, not in the Docker / Python / log lists. Excluding `/mnt` also excludes `/mnt/anything` underneath it. `/proc`, `/sys`, `/dev`, and `/run` are always skipped on top of this, and `/` itself can't be excluded.

After changing the setting, restart the container (`docker compose up -d`) — or try it out live first: the UI has an "Exclude from scan" box that applies immediately and rescans, but those changes only last until the container restarts. The compose setting is the permanent one.

## Cleanup

Cleanup is **off by default** (`ENABLE_CLEANUP=0`). The compose file turns it on. Buttons:

| Button | What it does |
|---|---|
| Prune unused images / volumes / build cache / system prune | Docker API prune calls — unused only |
| Truncate (log files) | Empties the file in place, keeps the file so the app writing it doesn't break |
| Delete (file / folder) | `rm` / `rm -rf` on exactly the path shown, after a confirm dialog |
| apt clean | `apt-get clean` (host-direct mode only) |
| Vacuum journal to 500M | `journalctl --vacuum-size=500M` (host-direct mode only) |

Safety, in the app not just in docs:

- Hard blocklist: `/`, `/bin`, `/boot`, `/etc`, `/lib`, `/sbin`, `/usr`, `/var/lib/docker` itself, and anything outside the scanned host root. Symlinks are resolved before the check.
- Every delete/truncate asks for confirmation in the UI.
- No login in v1 — **LAN / VPN only, never expose 8081 to the internet.**

Handy equivalents, for when you'd rather type them:

```bash
docker image prune -a            # unused images
docker volume prune              # unused volumes
docker builder prune -a          # build cache
docker system prune -a --volumes # all of the above + stopped containers
sudo journalctl --vacuum-size=500M
sudo apt-get clean
pip cache purge
# container logs: truncate, don't delete, while the container runs
sudo truncate -s 0 /var/lib/docker/containers/*/*-json.log
# log rotation so it doesn't come back: /etc/docker/daemon.json
#   { "log-driver": "json-file", "log-opts": { "max-size": "10m", "max-file": "3" } }
```

## How it works

- One file, `app.py`. A background thread walks the host root with `os.scandir`, totalling allocated disk (`st_blocks`, so it matches `du` more closely than apparent size), skipping `/proc`, `/sys`, `/dev`. It records every directory's total and the top 200 files, then builds the categories / Python / log lists from that scan.
- The UI polls `/api/summary` while a scan is running. Rescan from the dropdown (scan `/`, `/var`, `/var/lib/docker`, `/home`, …) or the Rescan button.
- First scan can take a minute or two on a big VM. Scan timeout is `SCAN_TIMEOUT` (default 300s); a timed-out scan keeps its partial results and says so.
- Docker data comes from the socket API, not from parsing `docker` CLI output. If no socket is mounted, the Docker section falls back to on-disk sizes for `/var/lib/docker/*`.

## Limits, stated plainly

- Sizes are allocated disk; Docker image sizes come from the API and are authoritative for images. Hardlinked layers / sparse files can make the filesystem walk and `docker system df` disagree — that's expected.
- No auth in v1. LAN only.
- `apt clean` / journal vacuum don't work from inside the container (see above).
- A scan is a snapshot — files created after it won't show until you rescan.
- CI builds the image on every push (`.github/workflows/build.yml` — syntax check, server smoke test, image build + container smoke test) and publishes it to GHCR on pushes to main (`ghcr.io/pete1450/disk-hog:latest` and `:<sha>`). It was **not** built in the agent VM (no Docker daemon there) — if the container doesn't come up on your host, check `docker logs diskhog` and the Actions tab.

## Files

- `app.py` — the whole app (backend + UI)
- `Dockerfile` — `python:3.13-slim` (currently Debian trixie-based), stdlib only
- `docker-compose.yml` — prod: one container per host, pulls the GHCR image
- `docker-compose.dev.yml` — dev override: build the image yourself instead

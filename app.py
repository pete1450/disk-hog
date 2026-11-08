#!/usr/bin/env python3
"""
DiskHog - what is eating disk on your Debian VMs, in one page.

Plain terms: it walks the host filesystem (mounted at /host in Docker,
or / when run directly), totals every directory, and shows:
  - disk overview per filesystem, with a bar
  - largest folders (click to drill down) and largest files
  - Docker: images / containers / volumes / build cache from the
    Docker API (system/df), plus on-disk docker dirs and container logs
  - Logs: /var/log, journal, and every *.log over 10 MB
  - Python: every installed python3.x tree, which one is current,
    which are pyenv / /usr/local / /opt (safe to remove) vs the
    distro python in /usr/lib (do NOT delete - apt and the OS use it)
  - Caches: apt, pip, npm, cargo, go, /tmp

Exclusions: EXCLUDE_PATHS=/mnt,/media (comma-separated, in
docker-compose.yml, or changed live from the UI) keeps those
trees out of the scan entirely - never walked, counted, or
shown. /proc, /sys, /dev and /run are always skipped.

Cleanup: every finding ships with the exact shell command to fix it,
and - when ENABLE_CLEANUP=1 - a button in the UI that runs it
(truncate a log, delete a file/dir, docker prune, apt clean,
journal vacuum). Cleanup is OFF by default. There is no login in
v1, so keep it on LAN / VPN only, exactly like SocketWatch.
A hard blocklist refuses to delete /, /bin, /boot, /etc, /lib,
/sbin, /usr, /var/lib/docker itself, and anything outside the
scanned host root.

Stdlib only. No pip packages, no CDN JS, no telemetry, nothing
leaves the machine. Run locally: python3 app.py (serves :8081).
Run in Docker: see docker-compose.yml.

Caveats, stated plainly:
  - Sizes are allocated disk (st_blocks), not apparent file size,
    so sparse files and hardlinked layers may read differently
    from `du` / `docker system df`. Docker image sizes come from
    the Docker API and are the authoritative ones for images.
  - A scan walks the whole disk; the first scan can take a minute
    or two on a big VM. It runs in the background, the UI polls it.
  - /proc, /sys, /dev are skipped (they are not real disk).
"""
import heapq
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOST_ROOT = os.environ.get("HOST_ROOT", "/host" if os.path.isdir("/host") else "/").rstrip("/") or "/"
# Display root: inside the container the host is at /host, show paths as /...
DISPLAY_ROOT = "/" if HOST_ROOT == "/host" else HOST_ROOT
PORT = int(os.environ.get("PORT", "8081"))
HOST = os.environ.get("HOST", "0.0.0.0")
ENABLE_CLEANUP = os.environ.get("ENABLE_CLEANUP", "0") == "1"
DOCKER_SOCK = os.environ.get("DOCKER_SOCK", "/var/run/docker.sock")
SCAN_TIMEOUT = float(os.environ.get("SCAN_TIMEOUT", "300"))
MAX_LARGEST_FILES = 200

SKIP_DIRS = {"proc", "sys", "dev", "run"}


def parse_exclude(value):
    """Comma-separated display paths -> sorted, de-duplicated list.
    Each entry must be absolute; '/' is ignored (it would exclude
    everything) and '..' is rejected. A path excludes itself and
    everything under it."""
    out = []
    for raw in (value or "").split(","):
        p = raw.strip().rstrip("/") or "/"
        if not p.startswith("/") or ".." in p.split("/"):
            continue
        if p == "/" or p in out:
            continue
        out.append(p)
    return sorted(out)


# Exclusion list, in display form (host paths as the user sees them,
# e.g. /mnt). Set with EXCLUDE_PATHS=/mnt,/media in the environment
# (docker-compose.yml), or changed live from the UI via /api/exclusions.
# /proc, /sys, /dev and /run are always skipped on top of this.
EXCLUDED = parse_exclude(os.environ.get("EXCLUDE_PATHS", ""))


def is_excluded(display_path):
    for ex in EXCLUDED:
        if display_path == ex or display_path.startswith(ex + "/"):
            return True
    return False
# Paths (display form, i.e. starting with /) that cleanup will never touch.
BLOCKED_EXACT = {"/", "/bin", "/boot", "/etc", "/lib", "/lib64", "/sbin",
                 "/usr", "/usr/bin", "/usr/lib", "/usr/local", "/var",
                 "/var/lib", "/var/lib/docker", "/home", "/root", "/opt"}
BLOCKED_PREFIXES = ("/bin/", "/boot/", "/etc/", "/lib/", "/lib64/",
                    "/sbin/", "/usr/bin/", "/var/lib/docker/image/",
                    "/var/lib/docker/overlay2/")

STATE = {"status": "idle", "started_at": 0, "finished_at": 0,
         "duration_s": 0, "files": 0, "dirs": 0, "errors": 0,
         "root": DISPLAY_ROOT, "message": ""}
RESULT = {"dirs": {}, "largest_files": [], "top_dirs": [],
          "categories": [], "python": [], "logs": [], "docker_fs": {}}
LOCK = threading.Lock()
SCAN_ID = [0]  # incremented by scan_async; a walk aborts when it changes


class ScanCancelled(Exception):
    pass


def log(msg):
    print(f"[diskhog] {msg}", flush=True)


def fmt(n):
    try:
        n = float(n)
    except (TypeError, ValueError):
        return "0 B"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


def to_host(path):
    """Display path (/var/log/...) -> real path on this machine."""
    if HOST_ROOT == "/":
        return path
    return HOST_ROOT + path


def to_display(path):
    if HOST_ROOT == "/" or not path.startswith(HOST_ROOT):
        return path
    disp = path[len(HOST_ROOT):] or "/"
    return disp


def allocated_size(st):
    # st_blocks is 512-byte units actually allocated on disk.
    try:
        return st.st_blocks * 512
    except AttributeError:
        return st.st_size


# ---------------------------------------------------------------- docker API
def docker_request(method, path, body=None):
    """Minimal HTTP-over-unix-socket, chunked-aware. Returns parsed JSON or None."""
    if not os.path.exists(DOCKER_SOCK):
        return None
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect(DOCKER_SOCK)
        payload = b""
        headers = f"{method} {path} HTTP/1.0\r\nHost: localhost\r\n".encode()
        if body is not None:
            payload = json.dumps(body).encode()
            headers += f"Content-Type: application/json\r\nContent-Length: {len(payload)}\r\n".encode()
        s.sendall(headers + b"\r\n" + payload)
        data = b""
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            data += chunk
        s.close()
        if b"\r\n\r\n" not in data:
            return None
        head, body_b = data.split(b"\r\n\r\n", 1)
        if b"chunked" in head.lower():
            out, rest = b"", body_b.strip()
            while rest:
                line, _, rest = rest.partition(b"\r\n")
                try:
                    size = int(line.strip(), 16)
                except ValueError:
                    break
                if size == 0:
                    break
                out += rest[:size]
                rest = rest[size + 2:]
            body_b = out
        if not body_b.strip():
            return {}
        return json.loads(body_b.decode(errors="replace"))
    except Exception as exc:
        log(f"docker api {method} {path} failed: {exc}")
        return None


def docker_info():
    """Images/containers/volumes/build-cache from `docker system df` + lists."""
    if not os.path.exists(DOCKER_SOCK):
        return {"available": False, "reason": "no docker socket mounted (add /var/run/docker.sock:ro)"}
    df = docker_request("GET", "/system/df") or {}
    images = docker_request("GET", "/images/json?all=0") or []
    containers = docker_request("GET", "/containers/json?all=1") or []
    volumes = docker_request("GET", "/volumes") or {}
    used_image_ids = set()
    for c in containers:
        used_image_ids.add(c.get("ImageID", ""))
        used_image_ids.add(c.get("Image", ""))
    img_rows = []
    for im in images:
        tags = im.get("RepoTags") or ["<none>:<none>"]
        img_rows.append({
            "id": (im.get("Id") or "")[7:19],
            "tags": tags,
            "size": im.get("Size", 0),
            "created": im.get("Created", 0),
            "dangling": not any(t and "<none>" not in t for t in tags),
            "in_use": (im.get("Id") in used_image_ids) or any(
                t in used_image_ids for t in tags),
        })
    img_rows.sort(key=lambda r: -r["size"])
    cont_rows = [{
        "id": (c.get("Id") or "")[:12],
        "name": (c.get("Names") or [""])[0].lstrip("/"),
        "image": c.get("Image", ""),
        "state": c.get("State", ""),
        "status": c.get("Status", ""),
        "size_rw": (c.get("SizeRw") or 0),
        "size_rootfs": (c.get("SizeRootFs") or 0),
    } for c in containers]
    vol_rows = []
    for v in (volumes.get("Volumes") or []):
        vol_rows.append({"name": v.get("Name", ""),
                         "driver": v.get("Driver", ""),
                         "mountpoint": v.get("Mountpoint", "")})
    layers = df.get("LayersSize") or 0
    return {"available": True,
            "images": img_rows,
            "images_total": sum(r["size"] for r in img_rows),
            "images_unused": sum(r["size"] for r in img_rows if not r["in_use"]),
            "images_dangling": sum(r["size"] for r in img_rows if r["dangling"]),
            "containers": cont_rows,
            "volumes": vol_rows,
            "build_cache": (df.get("BuildCache") or [{}])[0].get("Size", 0) if df.get("BuildCache") else 0,
            "layers_size": layers,
            "volumes_count": len(vol_rows),
            "containers_count": len(cont_rows),
            "images_count": len(img_rows)}


# ---------------------------------------------------------------- scanner
def _walk(path, depth, deadline, acc):
    """Recursive du. acc: dict with dir_sizes, largest heap, counts.
    Returns allocated size of this subtree."""
    try:
        entries = list(os.scandir(path))
    except OSError:
        acc["errors"] += 1
        return 0
    total = 0
    for entry in entries:
        if acc.get("scan_id") is not None and acc["scan_id"] != SCAN_ID[0]:
            raise ScanCancelled("superseded by a newer scan")
        if time.time() > deadline:
            raise TimeoutError("scan timed out")
        try:
            if entry.is_symlink():
                continue
            if entry.is_dir(follow_symlinks=False):
                if depth == 0 and entry.name in SKIP_DIRS:
                    continue
                if is_excluded(to_display(entry.path)):
                    continue
                # Never descend into the container's own /proc-style mounts
                # or into another mounted filesystem's pseudo dirs.
                total += _walk(entry.path, depth + 1, deadline, acc)
            elif entry.is_file(follow_symlinks=False):
                if is_excluded(to_display(entry.path)):
                    continue
                try:
                    st = entry.stat(follow_symlinks=False)
                except OSError:
                    acc["errors"] += 1
                    continue
                size = allocated_size(st)
                total += size
                acc["files"] += 1
                if len(acc["largest"]) < MAX_LARGEST_FILES or size > acc["largest"][0][0]:
                    heapq.heappush(acc["largest"], (size, to_display(entry.path),
                                                    int(st.st_mtime)))
                    if len(acc["largest"]) > MAX_LARGEST_FILES:
                        heapq.heappop(acc["largest"])
        except (OSError, RecursionError):
            acc["errors"] += 1
    acc["dirs"] += 1
    acc["dir_sizes"][to_display(path)] = total
    return total


def size_of_display(path):
    """One-off du of a single display path (for categories).
    Returns 0 for excluded paths, so categories / python / logs
    never count a subtree the scan itself skipped."""
    if is_excluded(path):
        return 0
    host = to_host(path)
    if not os.path.exists(host):
        return 0
    if os.path.isfile(host):
        try:
            return allocated_size(os.lstat(host))
        except OSError:
            return 0
    acc = {"largest": [], "files": 0, "dirs": 0, "errors": 0, "dir_sizes": {}}
    try:
        return _walk(host, 0, time.time() + 120, acc)
    except TimeoutError:
        return acc["dir_sizes"].get(path, 0)


def scan_root(root_display):
    root_host = to_host(root_display)
    my_id = SCAN_ID[0]
    with LOCK:
        STATE.update(status="scanning", started_at=time.time(),
                     finished_at=0, duration_s=0, files=0, dirs=0,
                     errors=0, root=root_display, message="")
    log(f"scan starting on {root_host}")
    acc = {"largest": [], "files": 0, "dirs": 0, "errors": 0, "dir_sizes": {},
           "scan_id": my_id}
    started = time.time()
    try:
        _walk(root_host, 0, started + SCAN_TIMEOUT, acc)
        status, message = "done", ""
    except ScanCancelled:
        log("scan superseded by a newer scan, discarding partial results")
        return
    except TimeoutError:
        status, message = "partial", f"scan hit the {SCAN_TIMEOUT:.0f}s limit - results are partial"
        log("scan timed out, keeping partial results")
    except RecursionError:
        status, message = "partial", "directory tree too deep - results are partial"
    largest = sorted(acc["largest"], key=lambda t: -t[0])
    largest_files = [{"path": p, "size": s, "mtime": m} for s, p, m in largest]
    # Children of root: direct subdirs recorded in dir_sizes.
    if root_display == "/":
        children = [d for d in acc["dir_sizes"] if d.count("/") == 1 and d != "/"]
    else:
        children = [d for d in acc["dir_sizes"]
                    if d.startswith(root_display.rstrip("/") + "/")
                    and d[len(root_display.rstrip("/")) + 1:].count("/") == 0]
    top = sorted(({"path": d, "size": acc["dir_sizes"][d]} for d in children),
                 key=lambda r: -r["size"])
    categories = build_categories(acc)
    python_rows = build_python(acc)
    logs_rows = build_logs(largest_files, acc)
    docker_fs = {k: acc["dir_sizes"].get(f"/var/lib/docker/{k}", 0) or
                 (size_of_display(f"/var/lib/docker/{k}") if os.path.exists(to_host(f"/var/lib/docker/{k}")) else 0)
                 for k in ("overlay2", "containers", "image", "volumes", "buildkit")}
    if my_id != SCAN_ID[0]:
        log("scan superseded while building categories, discarding")
        return
    with LOCK:
        RESULT.update(dirs=acc["dir_sizes"], largest_files=largest_files,
                      top_dirs=top, categories=categories,
                      python=python_rows, logs=logs_rows, docker_fs=docker_fs)
        STATE.update(status=status, finished_at=time.time(),
                     duration_s=time.time() - started, files=acc["files"],
                     dirs=acc["dirs"], errors=acc["errors"], message=message)
    log(f"scan {status}: {acc['files']} files, {acc['dirs']} dirs, "
        f"{time.time() - started:.1f}s, top={top[0]['path'] if top else '-'} "
        f"{fmt(top[0]['size']) if top else ''}")


def build_categories(acc):
    def cat_size(paths):
        total = 0
        for p in paths:
            total += acc["dir_sizes"].get(p, 0) or size_of_display(p)
        return total
    home = os.path.expanduser("~")
    defs = [
        ("Docker images & layers", ["/var/lib/docker/image", "/var/lib/docker/overlay2"],
         "docker image prune -a / docker system prune", "docker"),
        ("Docker container logs", ["/var/lib/docker/containers"],
         "truncate the *.log files, or set log rotation", "logs"),
        ("Docker volumes", ["/var/lib/docker/volumes"],
         "docker volume prune (only unused volumes)", "docker"),
        ("System logs", ["/var/log"],
         "journalctl --vacuum-size=500M, truncate old logs", "logs"),
        ("APT cache", ["/var/cache/apt"],
         "apt-get clean", "cache"),
        ("Python installs", ["/usr/lib/python3.11", "/usr/lib/python3.12",
                             "/usr/lib/python3.13", "/usr/local/lib"],
         "remove only pyenv / /usr/local / /opt versions, never distro python", "python"),
        ("pip cache", ["/root/.cache/pip", "/home/*/.cache/pip"],
         "pip cache purge", "cache"),
        ("/tmp & /var/tmp", ["/tmp", "/var/tmp"],
         "safe to clear files not in use", "cache"),
        ("Home caches", ["/root/.cache", "/home/*/.cache"],
         "npm / cargo / go caches live here", "cache"),
    ]
    out = []
    for label, paths, hint, kind in defs:
        # Expand /home/* globs by hand (no glob import needed for one case).
        real_paths = []
        for p in paths:
            if "*" in p:
                base = to_host(p.split("*")[0].rstrip("/"))
                try:
                    for name in os.listdir(base):
                        real_paths.append(p.replace("*", name))
                except OSError:
                    pass
            else:
                real_paths.append(p)
        size = 0
        for p in real_paths:
            size += acc["dir_sizes"].get(p, 0) or (size_of_display(p) if os.path.exists(to_host(p)) else 0)
        if size > 0:
            out.append({"label": label, "size": size, "hint": hint, "kind": kind,
                        "paths": real_paths})
    out.sort(key=lambda r: -r["size"])
    return out


def build_python(acc=None):
    """Every python tree on disk, with safety classification.
    Sizes come from the scan's dir_sizes when available, so this
    does not re-walk every python tree after the main scan."""
    current = f"{sys.version_info.major}.{sys.version_info.minor}"
    found = {}
    candidates = []
    host = to_host
    for base in ("/usr/lib", "/usr/local/lib", "/opt"):
        b = host(base)
        try:
            names = os.listdir(b)
        except OSError:
            continue
        for name in names:
            m = re.match(r"python(\d+\.\d+)$", name)
            if m:
                candidates.append((f"{base}/{name}", m.group(1)))
    # pyenv versions
    for home_base in ("/root/.pyenv/versions", "/home"):
        b = host(home_base)
        try:
            names = os.listdir(b)
        except OSError:
            continue
        if home_base.endswith("/home"):
            for user in names:
                vb = os.path.join(b, user, ".pyenv", "versions")
                try:
                    for v in os.listdir(vb):
                        candidates.append((f"/home/{user}/.pyenv/versions/{v}", v))
                except OSError:
                    pass
        else:
            for v in names:
                candidates.append((f"{home_base}/{v}", v))
    for path, ver in sorted(set(candidates)):
        if path in found:
            continue
        size = (acc or {}).get("dir_sizes", {}).get(path, 0) if acc else 0
        if not size:
            size = size_of_display(path)
        if size == 0:
            continue
        if path.startswith("/usr/lib/"):
            safety = "distro - DO NOT DELETE (apt / OS use it)"
            removable = False
        elif ".pyenv" in path or path.startswith(("/usr/local/", "/opt/")):
            safety = "safe to remove if unused (pyenv / local install)"
            removable = True
        else:
            safety, removable = "check before removing", False
        found[path] = {"path": path, "version": ver, "size": size,
                       "current": ver == current, "safety": safety,
                       "removable": removable,
                       "command": f"rm -rf {path}" if removable else ""}
    rows = sorted(found.values(), key=lambda r: -r["size"])
    return {"current": current, "rows": rows,
            "reclaimable": sum(r["size"] for r in rows if r["removable"] and not r["current"])}


def build_logs(largest_files, acc=None):
    rows = []
    for f in largest_files:
        if f["path"].endswith((".log", ".log.1", ".gz")) and "/log" in f["path"]:
            rows.append({**f, "kind": "log file"})
    # Journal size (a directory, not in largest-files).
    j = (acc or {}).get("dir_sizes", {}).get("/var/log/journal", 0) if acc else 0
    if not j:
        j = size_of_display("/var/log/journal")
    if j:
        rows.append({"path": "/var/log/journal", "size": j, "mtime": 0, "kind": "systemd journal"})
    rows.sort(key=lambda r: -r["size"])
    return rows[:30]


# ---------------------------------------------------------------- overview
def overview():
    mounts = []
    seen = set()
    try:
        with open(to_host("/proc/mounts")) as f:
            lines = f.readlines()
    except OSError:
        lines = []
    for line in lines:
        parts = line.split()
        if len(parts) < 2:
            continue
        mp = parts[1].replace("\\040", " ")
        if mp in seen or mp.startswith(("/proc", "/sys", "/dev", "/run/user")):
            continue
        seen.add(mp)
        try:
            u = shutil.disk_usage(to_host(mp) if HOST_ROOT != "/" else mp)
            mounts.append({"mount": mp if HOST_ROOT == "/" else to_display(mp) if mp.startswith(HOST_ROOT) else mp,
                           "total": u.total, "used": u.used, "free": u.free,
                           "pct": round(100 * u.used / u.total, 1) if u.total else 0})
        except OSError:
            continue
    if not mounts:
        try:
            u = shutil.disk_usage(HOST_ROOT)
            mounts.append({"mount": DISPLAY_ROOT, "total": u.total, "used": u.used,
                           "free": u.free, "pct": round(100 * u.used / u.total, 1) if u.total else 0})
        except OSError:
            pass
    mounts.sort(key=lambda m: -m["used"])
    return mounts


# ---------------------------------------------------------------- cleanup
def _blocked(path):
    if path in BLOCKED_EXACT:
        return True
    return any(path.startswith(p) for p in BLOCKED_PREFIXES)


def _resolve_display(path):
    """Return (host_path, error). Refuses escapes, symlinks out, blocked paths."""
    if not isinstance(path, str) or not path.startswith("/"):
        return None, "path must be absolute"
    if ".." in path.split("/"):
        return None, "path must not contain .."
    if _blocked(path):
        return None, f"{path} is on the protected list - use its shell command manually if you really mean it"
    host = to_host(path)
    real = os.path.realpath(host)
    host_root_real = os.path.realpath(HOST_ROOT)
    if host_root_real == "/":
        inside = real.startswith("/")
    else:
        inside = real == host_root_real or real.startswith(host_root_real + "/")
    if not inside:
        return None, "path escapes the scanned host root"
    if _blocked(to_display(real)):
        return None, "resolved path is protected"
    return real, None


def do_cleanup(action, target):
    """Returns (ok, message, freed_bytes). Only runs when ENABLE_CLEANUP=1."""
    if not ENABLE_CLEANUP:
        return False, "cleanup is disabled - set ENABLE_CLEANUP=1 in docker-compose.yml and restart", 0
    if action.startswith("docker_") and not os.path.exists(DOCKER_SOCK):
        return False, "no docker socket mounted - docker prune only works with /var/run/docker.sock mounted", 0
    if action == "docker_prune_images":
        r = docker_request("POST", "/images/prune?filters={\"dangling\":{\"false\":[\"true\"]}}")
        # The filter above prunes dangling only; a second call prunes unused.
        r2 = docker_request("POST", "/images/prune")
        freed = 0
        for res in (r, r2):
            if isinstance(res, dict):
                for item in res.get("ImagesDeleted") or []:
                    freed += item.get("Size", 0) if isinstance(item, dict) else 0
                freed += res.get("SpaceReclaimed", 0) or 0
        return True, "docker image prune done (dangling + unused)", freed
    if action == "docker_prune_volumes":
        r = docker_request("POST", "/volumes/prune")
        freed = (r or {}).get("SpaceReclaimed", 0) if isinstance(r, dict) else 0
        return True, "docker volume prune done (unused volumes only)", freed
    if action == "docker_prune_builder":
        r = docker_request("POST", "/build/prune?all=true")
        freed = (r or {}).get("SpaceReclaimed", 0) if isinstance(r, dict) else 0
        return True, "docker build cache pruned", freed
    if action == "docker_system_prune":
        docker_request("POST", "/containers/prune")
        docker_request("POST", "/images/prune")
        docker_request("POST", "/volumes/prune")
        docker_request("POST", "/build/prune?all=true")
        return True, "docker system prune done (stopped containers, unused images/volumes, build cache)", 0
    if action == "apt_clean":
        if HOST_ROOT != "/":
            return False, "apt clean only works when DiskHog runs directly on the host - run: sudo apt-get clean", 0
        r = subprocess.run(["apt-get", "clean"], capture_output=True, text=True, timeout=120)
        return r.returncode == 0, (r.stderr or "apt cache cleaned"), 0
    if action == "vacuum_journal":
        if HOST_ROOT != "/":
            return False, "journal vacuum only works when DiskHog runs directly on the host - run: sudo journalctl --vacuum-size=500M", 0
        size = target or "500M"
        if not re.fullmatch(r"\d+[KMG]", size):
            return False, "journal size must look like 500M", 0
        r = subprocess.run(["journalctl", f"--vacuum-size={size}"], capture_output=True, text=True, timeout=120)
        return r.returncode == 0, (r.stdout or r.stderr or f"journal vacuumed to {size}"), 0
    if action in ("truncate_log", "delete_path"):
        if not target:
            return False, "no target path given", 0
        real, err = _resolve_display(target)
        if err:
            return False, err, 0
        if action == "truncate_log":
            if not target.endswith((".log", ".log.1")):
                return False, "truncate only works on *.log files", 0
            try:
                size = os.path.getsize(real)
                with open(real, "w"):
                    pass
                return True, f"truncated {target} ({fmt(size)} freed)", size
            except OSError as exc:
                return False, str(exc), 0
        # delete_path
        try:
            if os.path.isdir(real) and not os.path.islink(real):
                size = size_of_display(target)
                shutil.rmtree(real)
            else:
                size = os.path.getsize(real)
                os.remove(real)
            return True, f"deleted {target} ({fmt(size)} freed)", size
        except OSError as exc:
            return False, str(exc), 0
    return False, f"unknown action: {action}", 0


def scan_async(root):
    # A new scan supersedes a running one: the old walk aborts on its
    # next entry (SCAN_ID check) and discards its partial results.
    SCAN_ID[0] += 1
    threading.Thread(target=scan_root, args=(root,), daemon=True).start()


# ---------------------------------------------------------------- web
INDEX_HTML = r"""<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>DiskHog — what's eating your disk</title>
<style>
body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:#111827;color:#e5e7eb;margin:0;padding:16px;max-width:1100px}
h1{font-size:22px;margin:0} h2{font-size:17px;margin:24px 0 8px;border-bottom:1px solid #374151;padding-bottom:4px}
p,li{color:#d1d5db;font-size:14px;line-height:1.45} .small{color:#9ca3af;font-size:12px}
code{background:#1f2937;padding:1px 5px;border-radius:4px;font-size:12px;overflow-wrap:anywhere}
button{background:#2563eb;color:#fff;border:0;border-radius:6px;padding:7px 12px;cursor:pointer;font-size:13px}
button.danger{background:#b91c1c} button.ghost{background:#374151} button:disabled{opacity:.45;cursor:not-allowed}
input,select{background:#1f2937;color:#e5e7eb;border:1px solid #374151;border-radius:6px;padding:6px 8px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:10px;margin:12px 0}
.card{background:#1f2937;border-radius:8px;padding:12px}
.card b{font-size:20px;display:block} .card span{color:#9ca3af;font-size:12px}
.bar{height:10px;background:#374151;border-radius:5px;overflow:hidden;margin-top:6px}
.bar>i{display:block;height:100%;background:#f59e0b}
.bar>i.ok{background:#22c55e} .bar>i.bad{background:#ef4444}
table{width:100%;border-collapse:collapse;font-size:13px}
th{text-align:left;border-bottom:1px solid #374151;padding:6px;white-space:nowrap}
td{border-bottom:1px solid #1f2937;padding:6px;vertical-align:top;overflow-wrap:anywhere}
tr:hover td{background:#1f2937}
.tag{display:inline-block;background:#374151;border-radius:4px;padding:1px 6px;font-size:11px;margin-right:4px}
.tag.red{background:#7c2d12} .tag.green{background:#14532d} .tag.amber{background:#78350f}
.row{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin:8px 0}
.breadcrumb button{margin-right:4px}
</style></head><body>
<h1>🐗 DiskHog</h1>
<p>What's eating disk on this host. Sizes are allocated disk. First scan can take a minute or two on a big VM — it runs in the background.</p>
<div class="row">
  <button id="rescan">↻ Rescan now</button>
  <select id="rootSel"></select>
  <span id="status" class="small"></span>
  <span id="cleanupState" class="small"></span>
</div>
<div class="row">
  <label class="small" for="excl">Exclude from scan:</label>
  <input id="excl" placeholder="/mnt,/media" size="32">
  <button class="ghost" id="applyExcl">Apply &amp; rescan</button>
  <span id="exclState" class="small"></span>
</div>
<p class="small">Excluded paths are never walked, counted, or shown. Change them here to try it out (lasts until the container restarts), or set EXCLUDE_PATHS in docker-compose.yml to keep them — comma-separated, e.g. <code>EXCLUDE_PATHS=/mnt,/media</code>.</p>
<div class="cards" id="overview"></div>

<h2>Where the space goes — categories</h2>
<p class="small">Known hogs, summed from the scan. Click a row's command to copy it.</p>
<table><thead><tr><th>Category</th><th>Size</th><th>What to do</th><th></th></tr></thead><tbody id="cats"></tbody></table>

<h2>Docker</h2>
<div id="docker"></div>

<h2>Python versions</h2>
<p class="small" id="pyNote"></p>
<table><thead><tr><th>Version</th><th>Path</th><th>Size</th><th>Safety</th><th></th></tr></thead><tbody id="pythons"></tbody></table>

<h2>Logs</h2>
<table><thead><tr><th>Path</th><th>Size</th><th>Kind</th><th></th></tr></thead><tbody id="logs"></tbody></table>

<h2>Largest folders <span class="small" id="crumb"></span></h2>
<div class="breadcrumb row" id="crumbs"></div>
<table><thead><tr><th>Folder</th><th>Size</th><th>Share</th></tr></thead><tbody id="folders"></tbody></table>

<h2>Largest files</h2>
<div class="row"><input id="q" placeholder="Filter files…" size="40"></div>
<table><thead><tr><th>File</th><th>Size</th><th>Modified</th><th></th></tr></thead><tbody id="files"></tbody></table>
<p class="small">Safety: cleanup buttons are off unless ENABLE_CLEANUP=1. Deletes never touch /, /bin, /boot, /etc, /lib, /sbin, /usr, /var/lib/docker, or anything outside the scanned host root. Every finding also shows its shell command, so you can do it by hand instead. No login in v1 — LAN / VPN only.</p>
<script>
let S=null, curRoot='/', curBrowse=null;
function esc(s){return String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]))}
function fmt(n){if(n<1024)return n+' B';const u=['KB','MB','GB','TB'];let i=-1;do{n/=1024;i++}while(n>=1024&&i<u.length-1);return n.toFixed(1)+' '+u[i]}
function copyCmd(t){navigator.clipboard?.writeText(t);t.textContent='copied ✓';setTimeout(()=>t.textContent='copy cmd',1200)}
async function load(){
  try{
    const r=await fetch('/api/summary'); S=await r.json(); render();
  }catch(e){document.getElementById('status').textContent='cannot reach backend';}
}
async function browse(path){
  const r=await fetch('/api/browse?path='+encodeURIComponent(path)); const j=await r.json();
  curBrowse=j; curRoot=path; renderFolders();
}
async function cleanup(action,target,btn){
  if(!confirm((action==='delete_path'?'DELETE ':'')+action+' '+target+' ?\nThis cannot be undone.')) return;
  btn.disabled=true;
  const r=await fetch('/api/cleanup',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action,target})});
  const j=await r.json(); alert((j.ok?'✓ ':'✗ ')+j.message+(j.ok?'\nHit Rescan for fresh numbers.':'')); load();
}
function render(){
  const st=S.state;
  document.getElementById('status').textContent = st.status==='scanning' ? `scanning ${esc(st.root)}… ${st.files} files so far` :
    `${st.status} · ${st.files} files · ${st.dirs} dirs · ${st.duration_s.toFixed(1)}s${st.message?' · '+esc(st.message):''}`;
  document.getElementById('cleanupState').textContent = S.cleanup_enabled ? 'cleanup: ON' : 'cleanup: OFF (set ENABLE_CLEANUP=1 to enable buttons)';
  document.getElementById('exclState').textContent = (S.exclusions && S.exclusions.length) ? 'excluding: '+S.exclusions.join(', ') : 'excluding: nothing (besides /proc, /sys, /dev, /run)';
  const excl=document.getElementById('excl');
  if(document.activeElement!==excl && S.exclusions) excl.value=S.exclusions.join(',');
  document.getElementById('overview').innerHTML = S.mounts.map(m=>`<div class="card"><b>${fmt(m.used)} / ${fmt(m.total)}</b><span>${esc(m.mount)} · ${m.pct}% used · ${fmt(m.free)} free</span><div class="bar"><i class="${m.pct>90?'bad':m.pct>75?'':'ok'}" style="width:${Math.min(m.pct,100)}%"></i></div></div>`).join('') || '<div class="card">no mounts found</div>';
  const sel=document.getElementById('rootSel');
  if(!sel.options.length){ ['/','/var','/var/lib/docker','/home','/usr','/opt','/tmp'].forEach(p=>{const o=document.createElement('option');o.value=p;o.textContent='scan '+p;sel.appendChild(o)}); sel.onchange=()=>{fetch('/api/scan',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({root:sel.value})}); curRoot=sel.value; load();}; }
  document.getElementById('cats').innerHTML = S.categories.map(c=>`<tr><td><b>${esc(c.label)}</b><br><span class="small">${esc(c.paths.join(', '))}</span></td><td>${fmt(c.size)}</td><td>${esc(c.hint)}</td><td>${c.kind==='docker'?`<button class="ghost" onclick="cleanup('docker_system_prune','',this)" ${S.cleanup_enabled?'':'disabled'}>prune docker</button>`:c.label.includes('APT')?`<button class="ghost" onclick="cleanup('apt_clean','',this)" ${S.cleanup_enabled?'':'disabled'}>apt clean</button>`:c.label.includes('System logs')?`<button class="ghost" onclick="cleanup('vacuum_journal','500M',this)" ${S.cleanup_enabled?'':'disabled'}>vacuum journal</button>`:''}</td></tr>`).join('') || '<tr><td colspan="4">No category over 0 yet — wait for the scan.</td></tr>';
  const d=S.docker;
  document.getElementById('docker').innerHTML = !d.available ? `<p>${esc(d.reason||'docker unavailable')}</p><p class="small">On-disk docker dirs (from the filesystem scan): overlay2 ${fmt(S.docker_fs.overlay2||0)} · containers ${fmt(S.docker_fs.containers||0)} · image ${fmt(S.docker_fs.image||0)} · volumes ${fmt(S.docker_fs.volumes||0)} · buildkit ${fmt(S.docker_fs.buildkit||0)}</p>`
   : `<div class="cards">
     <div class="card"><b>${fmt(d.images_total)}</b><span>${d.images_count} images · ${fmt(d.images_unused)} unused · ${fmt(d.images_dangling)} dangling</span></div>
     <div class="card"><b>${fmt(d.build_cache)}</b><span>build cache</span></div>
     <div class="card"><b>${d.containers_count}</b><span>containers · ${d.volumes_count} volumes</span></div>
     <div class="card"><b>${fmt(S.docker_fs.overlay2||0)}</b><span>overlay2 on disk · logs ${fmt(S.docker_fs.containers||0)}</span></div></div>
   <div class="row"><button onclick="cleanup('docker_prune_images','',this)" ${S.cleanup_enabled?'':'disabled'}>Prune unused images</button>
   <button onclick="cleanup('docker_prune_volumes','',this)" ${S.cleanup_enabled?'':'disabled'}>Prune unused volumes</button>
   <button onclick="cleanup('docker_prune_builder','',this)" ${S.cleanup_enabled?'':'disabled'}>Prune build cache</button>
   <button class="danger" onclick="cleanup('docker_system_prune','',this)" ${S.cleanup_enabled?'':'disabled'}>docker system prune</button></div>
   <table><thead><tr><th>Image</th><th>Size</th><th>Created</th><th>Status</th></tr></thead><tbody>
   ${d.images.slice(0,30).map(i=>`<tr><td>${esc(i.tags.join(', '))}<br><span class="small">${esc(i.id)}</span></td><td>${fmt(i.size)}</td><td class="small">${i.created?new Date(i.created*1000).toLocaleDateString():'—'}</td><td>${i.dangling?'<span class="tag red">dangling</span>':''}${i.in_use?'<span class="tag green">in use</span>':'<span class="tag amber">unused</span>'}</td></tr>`).join('')}</tbody></table>
   <p class="small">Or by hand: <code>docker image prune -a</code> (unused), <code>docker volume prune</code>, <code>docker builder prune -a</code>, <code>docker system prune -a --volumes</code>. Unused = no container references it.</p>`;
  document.getElementById('pyNote').textContent = `Current python for this app: ${S.python.current}. Distro python in /usr/lib is used by apt and the OS — never delete it. Only pyenv / /usr/local / /opt versions are safe to remove, and only if nothing uses them. Reclaimable from removable non-current versions: ${fmt(S.python.reclaimable||0)}.`;
  document.getElementById('pythons').innerHTML = S.python.rows.map(p=>`<tr><td>${esc(p.version)}${p.current?' <span class="tag green">current</span>':''}</td><td>${esc(p.path)}</td><td>${fmt(p.size)}</td><td class="small">${esc(p.safety)}</td><td>${p.removable&&!p.current?`<button class="danger" onclick="cleanup('delete_path','${esc(p.path)}',this)" ${S.cleanup_enabled?'':'disabled'}>delete</button> <button class="ghost" onclick="copyCmd(this)" data-cmd="${esc(p.command)}">copy cmd</button>`:''}</td></tr>`).join('') || '<tr><td colspan="5">No python trees found yet.</td></tr>';
  document.getElementById('logs').innerHTML = S.logs.map(l=>`<tr><td>${esc(l.path)}</td><td>${fmt(l.size)}</td><td>${esc(l.kind)}</td><td>${l.kind==='log file'?`<button onclick="cleanup('truncate_log','${esc(l.path)}',this)" ${S.cleanup_enabled?'':'disabled'}>truncate</button>`:l.kind==='systemd journal'?`<button onclick="cleanup('vacuum_journal','500M',this)" ${S.cleanup_enabled?'':'disabled'}>vacuum to 500M</button>`:''}</td></tr>`).join('') || '<tr><td colspan="4">No big logs found yet.</td></tr>';
  renderFolders(); renderFiles();
}
function renderFolders(){
  const rows = curBrowse ? curBrowse.children : S.top_dirs;
  const total = rows.reduce((a,r)=>a+r.size,0) || 1;
  document.getElementById('crumb').textContent = '— '+curRoot;
  document.getElementById('crumbs').innerHTML = `<button class="ghost" onclick="browse('/')">/</button>` + (curRoot!=='/'?`<span>${esc(curRoot)}</span> <button class="ghost" onclick="browse('/')">back to /</button>`:'');
  document.getElementById('folders').innerHTML = rows.map(r=>`<tr><td><a href="#" onclick="browse('${esc(r.path)}');return false">${esc(r.path)}</a></td><td>${fmt(r.size)}</td><td><div class="bar"><i style="width:${Math.min(100,100*r.size/total)}%"></i></div></td></tr>`).join('') || '<tr><td colspan="3">Nothing here yet — wait for the scan, or rescan.</td></tr>';
}
function renderFiles(){
  const q=(document.getElementById('q').value||'').toLowerCase();
  const rows=S.largest_files.filter(f=>!q||f.path.toLowerCase().includes(q)).slice(0,100);
  document.getElementById('files').innerHTML = rows.map(f=>`<tr><td>${esc(f.path)}</td><td>${fmt(f.size)}</td><td class="small">${f.mtime?new Date(f.mtime*1000).toLocaleDateString():'—'}</td><td>${f.path.endsWith('.log')?`<button onclick="cleanup('truncate_log','${esc(f.path)}',this)" ${S.cleanup_enabled?'':'disabled'}>truncate</button> `:`<button class="danger" onclick="cleanup('delete_path','${esc(f.path)}',this)" ${S.cleanup_enabled?'':'disabled'}>delete</button>`}</td></tr>`).join('') || '<tr><td colspan="4">No files yet.</td></tr>';
}
document.getElementById('rescan').onclick=()=>{fetch('/api/scan',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({root:curRoot})}); setTimeout(load,500);};
document.getElementById('applyExcl').onclick=async()=>{
  const v=document.getElementById('excl').value;
  const r=await fetch('/api/exclusions',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({paths:v})});
  const j=await r.json(); document.getElementById('exclState').textContent=j.message||''; setTimeout(load,500);
};
document.getElementById('q').addEventListener('input',renderFiles);
load(); setInterval(()=>{ if(S && S.state.status==='scanning') load(); },3000);
</script></body></html>
"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def send_json(self, obj, status=200):
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/":
            body = INDEX_HTML.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/health":
            self.send_json({"ok": True, "cleanup_enabled": ENABLE_CLEANUP})
        elif self.path == "/api/summary":
            with LOCK:
                snap = {"state": dict(STATE), "mounts": overview(),
                        "categories": list(RESULT["categories"]),
                        "python": RESULT["python"] or {"current": f"{sys.version_info.major}.{sys.version_info.minor}", "rows": [], "reclaimable": 0},
                        "logs": list(RESULT["logs"]),
                        "top_dirs": list(RESULT["top_dirs"]),
                        "largest_files": list(RESULT["largest_files"]),
                        "docker": docker_info(), "docker_fs": dict(RESULT["docker_fs"]),
                        "cleanup_enabled": ENABLE_CLEANUP,
                        "exclusions": list(EXCLUDED)}
            self.send_json(snap)
        elif self.path.startswith("/api/browse"):
            from urllib.parse import urlparse, parse_qs
            path = parse_qs(urlparse(self.path).query).get("path", ["/"])[0]
            with LOCK:
                dirs = dict(RESULT["dirs"])
            prefix = path.rstrip("/") + "/"
            children = [{"path": d, "size": dirs[d]} for d in dirs
                        if d.startswith(prefix) and "/" not in d[len(prefix):]]
            children.sort(key=lambda r: -r["size"])
            self.send_json({"path": path, "children": children[:50]})
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            payload = json.loads(raw.decode() or "{}")
        except json.JSONDecodeError:
            payload = {}
        if self.path == "/api/scan":
            root = payload.get("root") or "/"
            if not root.startswith("/"):
                self.send_json({"ok": False, "message": "root must be absolute"}, 400)
                return
            scan_async(root)
            self.send_json({"ok": True, "message": f"scan of {root} started"})
        elif self.path == "/api/exclusions":
            global EXCLUDED
            raw = payload.get("paths", payload.get("exclude_paths", ""))
            if isinstance(raw, list):
                raw = ",".join(str(p) for p in raw)
            EXCLUDED = parse_exclude(raw)
            log(f"exclusions set to {EXCLUDED} (in-memory; set EXCLUDE_PATHS to keep them after restart)")
            scan_async(STATE.get("root", "/"))
            self.send_json({"ok": True, "exclusions": list(EXCLUDED),
                            "message": f"exclusions updated ({', '.join(EXCLUDED) or 'none'}) - rescanning. "
                            "To keep them after a restart, set EXCLUDE_PATHS in docker-compose.yml."})
        elif self.path == "/api/cleanup":
            ok, message, freed = do_cleanup(payload.get("action", ""), payload.get("target", ""))
            self.send_json({"ok": ok, "message": message, "freed": freed},
                           200 if ok else 400)
            # No auto-rescan: a cleanup of a file under / would otherwise
            # trigger a full-disk rescan on every click. The UI tells
            # the user to hit Rescan when they want fresh numbers.
        else:
            self.send_response(404)
            self.end_headers()


if __name__ == "__main__":
    if os.environ.get("AUTOSCAN", "1") == "1":
        scan_async("/")
    log(f"serving on http://{HOST}:{PORT} (HOST_ROOT={HOST_ROOT}, cleanup={'ON' if ENABLE_CLEANUP else 'OFF'})")
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()

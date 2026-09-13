#!/usr/bin/env python3
# coding: utf-8
"""音乐解锁后台服务 + 管理控制台 (零依赖, 仅 Python 标准库)。

用法:
  python webui.py                 # 前台运行 (开发/调试)
  python webui.py --daemon        # 后台守护进程运行
  python webui.py --stop          # 停止后台服务
  python webui.py --status        # 查看服务状态
  python webui.py --port 9000     # 覆盖配置文件端口

配置文件默认存到项目根 config.json (如已存在旧的 ~/.music-unlock/config.json 则沿用),
任务历史与守护日志仍放在 ~/.music-unlock/。
"""
from __future__ import annotations

import argparse
import collections
import concurrent.futures
import json
import os
import queue
import secrets
import shutil
import ssl
import threading
import time
import urllib.parse
import urllib.request
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from music_unlock.core import decrypt_bytes, decrypt_file
from music_unlock.formats import FORMATS, DecryptError, _ENCRYPTED_SUFFIXES, detect_format
from music_unlock import kgg_keys
from music_unlock.sniff import sniff_audio

APP_NAME = "music-unlock"
PROJECT_ROOT = Path(__file__).resolve().parent
BASE_DIR = Path.home() / ("." + APP_NAME)
HOME_CONFIG = BASE_DIR / "config.json"
CONFIG_PATH = PROJECT_ROOT / "config.json"
JOBS_PATH = BASE_DIR / "jobs.json"
LOG_PATH = BASE_DIR / "service.log"
PID_PATH = BASE_DIR / "pid"
KGG_DB_CACHE = BASE_DIR / "KGMusicV3.db"
KGG_KEY_CACHE = BASE_DIR / "kgg.key"
_HTML_PATH = PROJECT_ROOT / "webui.html"
_VERSION = "0.3.0"
_UPLOAD_TTL = 600
SERVER_START = time.time()


class Log:
    def __init__(self, maxlen: int = 1000):
        self._buf = collections.deque(maxlen=maxlen)
        self._lock = threading.Lock()

    def add(self, msg: str, level: str = "info"):
        with self._lock:
            self._buf.append((time.time(), level, str(msg)))

    def snapshot(self):
        with self._lock:
            return list(self._buf)


LOG = Log()


def log(msg, level="info"):
    LOG.add(msg, level)
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def _config_path() -> Path:
    """配置文件路径：环境变量 > 项目根 config.json > 旧的 ~/.music-unlock/config.json > 项目根。"""
    env = os.environ.get("MUSIC_UNLOCK_CONFIG")
    if env:
        return Path(env).expanduser()
    if CONFIG_PATH.exists():
        return CONFIG_PATH
    if HOME_CONFIG.exists():
        return HOME_CONFIG
    return CONFIG_PATH


class Config:
    DEFAULTS = {
        "host": "127.0.0.1",
        "port": 8765,
        "outdir": "",
        "force": False,
        "delete_source": False,
        "recursive": False,
        "concurrency": 3,
        "kgg_db": "",
        "kgg_key": "",
    }

    def __init__(self, path: Path | None = None):
        self.path = path or _config_path()
        self._lock = threading.Lock()
        self.data = dict(self.DEFAULTS)
        self.load()

    def load(self):
        try:
            raw = json.loads(self.path.read_text("utf-8"))
            for k in self.DEFAULTS:
                if k in raw:
                    self.data[k] = raw[k]
        except (OSError, ValueError):
            pass

    def get(self):
        with self._lock:
            return dict(self.data)

    def update(self, patch: dict):
        with self._lock:
            for k in patch:
                if k in self.DEFAULTS:
                    self.data[k] = patch[k]
            data = dict(self.data)
        self.save()
        return data

    def save(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._lock:
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(self.data, ensure_ascii=False, indent=2), "utf-8")
            os.replace(tmp, self.path)


CONFIG = Config()


class Job:
    def __init__(self, path: Path | None, items: list[str], opts: dict, name: str = ""):
        self.id = secrets.token_hex(6)
        self.created = time.time()
        if name and name.strip():
            self.name = name.strip()
        else:
            self.name = str(path) if path else "批量任务"
        self.items = [
            {"src": p, "dest": "", "status": "pending", "msg": ""}
            for p in items
        ]
        self.outdir = Path(opts.get("outdir")) if opts.get("outdir") else None
        self.base_outdir = str(self.outdir) if self.outdir else None
        self.force = bool(opts.get("force"))
        self.delete = bool(opts.get("delete"))
        self.concurrency = max(1, int(opts.get("concurrency") or 1))
        self.status = "running"
        self.started = 0.0
        self.finished = None
        self._stop = threading.Event()
        self._lock = threading.Lock()

    def to_dict(self, detail: bool = False):
        d = {
            "id": self.id,
            "name": self.name,
            "created": self.created,
            "status": self.status,
            "total": len(self.items),
            "done": sum(1 for i in self.items if i["status"] in ("ok", "skip", "fail")),
            "ok": sum(1 for i in self.items if i["status"] == "ok"),
            "skip": sum(1 for i in self.items if i["status"] == "skip"),
            "fail": sum(1 for i in self.items if i["status"] == "fail"),
            "running": sum(1 for i in self.items if i["status"] == "running"),
            "outdir": self.base_outdir,
            "force": self.force,
            "delete": self.delete,
            "started": self.started,
            "finished": self.finished,
            "duration": None,
        }
        if self.started:
            d["duration"] = round(self.finished - self.started, 1) if self.finished else round(time.time() - self.started, 1)
        if detail:
            d["items"] = self.items
        return d


class Jobs:
    def __init__(self, path: Path = JOBS_PATH):
        self.path = path
        self._jobs: dict[str, Job] = {}
        self._lock = threading.Lock()
        self._load()

    def add(self, job: Job) -> str:
        with self._lock:
            self._jobs[job.id] = job
        self._persist()
        log(f"任务已创建: {job.name} ({len(job.items)} 个文件)")
        threading.Thread(target=self._run, args=(job,), daemon=True).start()
        notify_jobs()
        return job.id

    def stop(self, jid: str) -> bool:
        with self._lock:
            job = self._jobs.get(jid)
        if not job or job.status != "running":
            return False
        job._stop.set()
        job.status = "stopping"
        notify_jobs()
        return True

    def get(self, jid: str) -> Job | None:
        with self._lock:
            return self._jobs.get(jid)

    def delete(self, jid: str) -> bool:
        with self._lock:
            job = self._jobs.get(jid)
            if not job:
                return False
            if job.status == "running":
                job._stop.set()
                job.status = "stopping"
            del self._jobs[jid]
        self._persist()
        log(f"任务已删除: {job.name}")
        notify_jobs()
        return True

    def delete_all(self) -> int:
        with self._lock:
            count = 0
            for job in list(self._jobs.values()):
                if job.status == "running":
                    job._stop.set()
                    job.status = "stopping"
                count += 1
            self._jobs.clear()
        self._persist()
        log(f"已清空 {count} 条任务记录")
        notify_jobs()
        return count

    def list(self) -> list[dict]:
        with self._lock:
            jobs = list(self._jobs.values())
        return [j.to_dict() for j in sorted(jobs, key=lambda x: x.created, reverse=True)]

    def _run(self, job: Job):
        job.started = time.time()
        sem = threading.Semaphore(job.concurrency)

        def work(item):
            if job._stop.is_set():
                return
            sem.acquire()
            try:
                item["status"] = "running"
                self._do(job, item)
            except Exception as e:
                item["status"] = "fail"
                item["msg"] = f"处理异常: {e}"
            finally:
                sem.release()
                notify_jobs()

        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=job.concurrency) as ex:
                ex.map(work, job.items)
        finally:
            job.status = "stopped" if job.status == "stopping" else "done"
            job.finished = time.time()
            self._persist()
            c = job.to_dict()
            log(f"任务完成: {job.name} [成功 {c['ok']} / 跳过 {c['skip']} / 失败 {c['fail']}]")
            notify_jobs()

    def _do(self, job: Job, item: dict):
        src = Path(item["src"])
        msg = decrypt_file(
            src,
            job.outdir,
            job.force,
            job.delete,
            verbose=True,
        )
        item["msg"] = msg
        if not msg:
            item["status"] = "skip"
            item["msg"] = "不可处理或已跳过"
            return
        if msg.startswith("跳过"):
            item["status"] = "skip"
            return
        if (msg.startswith("失败") or msg.startswith("读取失败")
                or msg.startswith("输出目录不可用")):
            item["status"] = "fail"
            return
        # 成功: "源名 -> 目标名 [.ext] (...)"
        item["status"] = "ok"
        try:
            arrow = msg.split(" -> ")[1]
            out_name = arrow.split(" [")[0]
            base = job.outdir if job.outdir else src.parent
            item["dest"] = str(Path(base) / out_name)
        except Exception:
            item["dest"] = ""

    def _persist(self):
        with self._lock:
            payload = {"apps": {"version": _VERSION}, "jobs": [j.to_dict(detail=True) for j in self._jobs.values()]}
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(payload, ensure_ascii=False), "utf-8")
            os.replace(tmp, self.path)
        except OSError as e:
            log(f"任务持久化失败: {e}", "warn")

    def _load(self):
        try:
            payload = json.loads(self.path.read_text("utf-8"))
            for j in payload.get("jobs", []):
                job = Job.__new__(Job)
                job.id = j["id"]
                job.name = j["name"]
                job.created = j["created"]
                job.items = j["items"]
                job.outdir = Path(j["outdir"]) if j.get("outdir") else None
                job.base_outdir = j.get("outdir")
                job.force = j.get("force", False)
                job.delete = j.get("delete", False)
                job.concurrency = j.get("concurrency", 1)
                job.status = j.get("status")
                job.started = j.get("started", 0.0)
                job.finished = j.get("finished")
                job._stop = threading.Event()
                job._lock = threading.Lock()
                self._jobs[job.id] = job
        except (OSError, ValueError):
            pass


JOBS = Jobs()


# --- Server-Sent Events (实时推送) ---
_SSE_LOCK = threading.Lock()
_SSE_CLIENTS: set[queue.Queue] = set()


def notify_jobs():
    """广播「任务列表已变化」给所有 SSE 订阅者。"""
    with _SSE_LOCK:
        clients = list(_SSE_CLIENTS)
    for q in clients:
        q.put("jobs")


def _scan_dir(directory: Path, recursive: bool) -> list[dict]:
    files: list[Path] = []
    if directory.is_file():
        files = [directory]
    elif directory.is_dir():
        files = list(directory.rglob("*") if recursive else directory.iterdir())
        files = [p for p in files if p.is_file()]
    out = []
    SUFF = tuple(_ENCRYPTED_SUFFIXES)
    for p in files:
        try:
            header = p.open("rb").read(1024)
        except OSError:
            continue
        fmt = detect_format(header, p.suffix)
        if fmt is None and p.suffix.lower() not in SUFF:
            continue
        out.append({
            "path": str(p),
            "name": p.name,
            "size": p.stat().st_size if p.exists() else 0,
            "ext": p.suffix,
            "fmt": fmt.name if fmt else "unknown",
        })
    return out


def _explore(directory: Path, recursive: bool = False) -> dict:
    entries = []
    if not directory.exists() or not directory.is_dir():
        return {"path": str(directory), "exists": False, "entries": [], "recursive": recursive}
    try:
        paths = sorted(directory.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower()))
    except OSError as e:
        return {"path": str(directory), "exists": True, "error": str(e), "entries": [], "recursive": recursive}
    SUFF = tuple(_ENCRYPTED_SUFFIXES)

    # 1. 始终展示当前层子目录，便于进入下一层
    for p in paths:
        if p.is_dir():
            entries.append({"name": p.name, "path": str(p), "type": "dir"})

    # 2. 当前目录直接文件
    for p in paths:
        if not p.is_dir():
            try:
                header = p.open("rb").read(1024)
                fmt = detect_format(header, p.suffix)
                if fmt is None and p.suffix.lower() not in SUFF:
                    continue
                entries.append({
                    "name": p.name, "path": str(p), "type": "file",
                    "size": p.stat().st_size,
                    "fmt": fmt.name if fmt else "unknown",
                    "ext": p.suffix,
                })
            except OSError:
                continue

    # 3. 若开启递归，额外汇总所有子目录中的加密文件（相对路径展示，避免重复）
    if recursive:
        try:
            for p in sorted(directory.rglob("*"), key=lambda x: str(x).lower()):
                if not p.is_file() or p.parent == directory:
                    continue
                try:
                    header = p.open("rb").read(1024)
                    fmt = detect_format(header, p.suffix)
                    if fmt is None and p.suffix.lower() not in SUFF:
                        continue
                    entries.append({
                        "name": str(p.relative_to(directory)),
                        "path": str(p),
                        "type": "file",
                        "size": p.stat().st_size,
                        "fmt": fmt.name if fmt else "unknown",
                        "ext": p.suffix,
                    })
                except OSError:
                    continue
        except OSError:
            pass

    return {"path": str(directory), "exists": True, "entries": entries, "recursive": recursive}


#
# upload store (快速上传解密)
#
class UploadStore:
    def __init__(self, ttl: int):
        self._map: dict[str, tuple[float, dict]] = {}
        self._ttl = ttl

    def put(self, item: dict) -> str:
        token = secrets.token_urlsafe(24)
        self._map[token] = (time.time(), item)
        return token

    def peek(self, token: str) -> dict | None:
        val = self._map.get(token)
        return val[1] if val else None

    def pop(self, token: str) -> dict | None:
        val = self._map.pop(token, None)
        return val[1] if val else None

    def purge(self):
        now = time.time()
        for t in [k for k, (ts, _) in self._map.items() if now - ts > self._ttl]:
            self._map.pop(t, None)


STORE = UploadStore(_UPLOAD_TTL)

_BING_API = ("https://www.bing.com/HPImageArchive.aspx?format=js"
             "&idx=0&n={n}&mkt=zh-CN")
_BING_CACHE: dict = {}
_BING_CACHE_TTL: int = 3600 * 4
_BING_LOCK = threading.Lock()
_KG_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
          "AppleWebKit/537.36 (KHTML, like Gecko) "
          "Chrome/124.0.0.0 Safari/537.36")
_KG_SSL = ssl.create_default_context()


def _fetch_bing(count: int = 8) -> list[str]:
    """Fetch Bing daily wallpapers (cached)."""
    with _BING_LOCK:
        now = time.time()
        if "urls" in _BING_CACHE and now - _BING_CACHE.get("ts", 0) < _BING_CACHE_TTL:
            return _BING_CACHE["urls"]
    try:
        url = _BING_API.format(n=count)
        req = urllib.request.Request(url, headers={"User-Agent": _KG_UA})
        with urllib.request.urlopen(req, timeout=8, context=_KG_SSL) as resp:
            data = json.loads(resp.read())
        urls = ["https://www.bing.com" + im["url"] for im in data.get("images", [])]
        with _BING_LOCK:
            _BING_CACHE["urls"] = urls
            _BING_CACHE["ts"] = time.time()
        return urls
    except Exception:
        with _BING_LOCK:
            return _BING_CACHE.get("urls", [])


def _output_dir() -> Path:
    cfg = CONFIG.get()
    return Path(cfg.get("outdir")) if cfg.get("outdir") else PROJECT_ROOT / "output"


def _load_kgg_from_config() -> None:
    """启动时按 config 里的 kgg_db / kgg_key 预加载酷狗密钥映射。"""
    cfg = CONFIG.get()
    for key, cls in (("kgg_db", "db"), ("kgg_key", "key")):
        path = cfg.get(key)
        if not path or not Path(path).is_file():
            continue
        try:
            if cls == "db":
                n = kgg_keys.configure(db_path=path)
            else:
                n = kgg_keys.configure(key_path=path)
            log(f"酷狗密钥库已加载: {path} ({n} 条)")
        except kgg_keys.KggKeyError as e:
            log(f"酷狗密钥库加载失败: {path} ({e})", "warn")
        return


def _list_output_files() -> list[dict]:
    """List files in the output directory."""
    outdir = _output_dir()
    if not outdir.exists():
        return []
    files = []
    for p in sorted(outdir.rglob("*"), key=lambda x: str(x).lower()):
        if p.is_file():
            try:
                files.append({
                    "name": str(p.relative_to(outdir)),
                    "path": str(p),
                    "size": p.stat().st_size,
                    "ext": p.suffix,
                })
            except OSError:
                continue
    return files


def _content_disposition(name: str) -> str:
    """Build a filename-safe Content-Disposition header (RFC 6266 / 5987).

    - ``filename`` 提供纯 ASCII 安全回退名（避免部分浏览器因中文/特殊字符
      导致文件名残缺或无法保存）。
    - ``filename*`` 提供完整 UTF-8 编码名，供现代浏览器正确显示。
    """
    p = Path(name)
    stem = p.stem
    suffix = p.suffix

    def _safe(s: str) -> str:
        return "".join(c for c in s if c.isascii() and (c.isalnum() or c in "-_."))

    fallback_stem = _safe(stem).strip()
    if not fallback_stem or fallback_stem != stem:
        fallback_stem = "download"
    fallback = fallback_stem + _safe(suffix)

    encoded = urllib.parse.quote(name, safe="")
    return f"attachment; filename=\"{fallback}\"; filename*=UTF-8''{encoded}"


class Handler(BaseHTTPRequestHandler):
    server_version = APP_NAME + "/" + _VERSION

    def log_message(self, fmt, *args):
        msg = f"{self.address_string()} {fmt % args}"
        if "200" not in (args[1] if len(args) > 1 else ""):
            log(msg, "debug")

    def _json(self, data, status=200):
        body = json.dumps(data, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", len(body))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _html(self, path: Path):
        try:
            body = path.read_bytes()
        except OSError:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", len(body))
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(length) if length else b""

    def _parse_json(self) -> dict:
        try:
            return json.loads(self._read_body())
        except (json.JSONDecodeError, ValueError):
            return {}

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def _handle_sse(self):
        q = queue.Queue()
        with _SSE_LOCK:
            _SSE_CLIENTS.add(q)
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache, no-store")
        self.send_header("Connection", "keep-alive")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        try:
            self.wfile.write(b"retry: 2000\n\n")
            self.wfile.flush()
            while True:
                try:
                    q.get(timeout=15)
                    self.wfile.write(b"data: jobs\n\n")
                    self.wfile.flush()
                except queue.Empty:
                    self.wfile.write(b": ping\n\n")
                    self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            with _SSE_LOCK:
                _SSE_CLIENTS.discard(q)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        qs = dict(urllib.parse.parse_qsl(parsed.query))

        if path == "/api/events":
            return self._handle_sse()

        if path in ("/", "/index.html"):
            return self._html(_HTML_PATH)

        if path == "/api/formats":
            return self._json({"formats": [
                {"name": f.name, "suffixes": list(f.suffixes)}
                for f in FORMATS
            ]})

        if path == "/api/config":
            return self._json({"config": CONFIG.get()})

        if path == "/api/kgg/status":
            km = kgg_keys.get()
            cfg = CONFIG.get()
            return self._json({
                "loaded": km is not None,
                "count": len(km) if km else 0,
                "source": kgg_keys.source(),
                "kgg_db": cfg.get("kgg_db", ""),
                "kgg_key": cfg.get("kgg_key", ""),
            })

        if path == "/api/explore":
            d = qs.get("dir", "")
            recursive = qs.get("recursive", "0") == "1"
            if not d:
                d = str(PROJECT_ROOT)
            result = _explore(Path(d), recursive)
            return self._json(result)

        if path == "/api/scan":
            d = qs.get("dir", "")
            recursive = qs.get("recursive", "0") == "1"
            if not d:
                d = str(PROJECT_ROOT)
            files = _scan_dir(Path(d), recursive)
            return self._json({"files": files})

        if path == "/api/jobs":
            jid = qs.get("id")
            if jid:
                job = JOBS.get(jid)
                if not job:
                    return self._json({"error": "任务不存在"}, 404)
                return self._json({"job": job.to_dict(detail=True)})
            return self._json({"jobs": JOBS.list()})

        if path == "/api/logs":
            limit = int(qs.get("limit", "200"))
            snaps = LOG.snapshot()
            logs = [{"ts": t, "level": l, "msg": m} for t, l, m in snaps[-limit:]]
            return self._json({"logs": logs})

        if path == "/api/output":
            return self._json({"files": _list_output_files()})

        if path == "/api/output/download":
            name = qs.get("path", "")
            base = _output_dir().resolve()
            try:
                p = (base / name).resolve()
                p.relative_to(base)
            except (ValueError, OSError):
                return self._json({"error": "无效的路径"}, 400)
            if not p.is_file():
                return self._json({"error": "文件不存在"}, 404)
            data = p.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Disposition", _content_disposition(p.name))
            self.send_header("Content-Length", len(data))
            self.send_header("Connection", "close")
            self.close_connection = True
            self.end_headers()
            self.wfile.write(data)
            return

        if path == "/api/health":
            uptime = round(time.time() - SERVER_START, 1)
            return self._json({
                "status": "ok",
                "version": _VERSION,
                "uptime": uptime,
                "pid": os.getpid(),
                "jobs": len(JOBS.list()),
                "formats": [f.name for f in FORMATS],
            })

        if path == "/api/bing":
            count = int(qs.get("n", "8"))
            urls = _fetch_bing(count)
            return self._json({"urls": urls})

        if path == "/api/download":
            token = qs.get("token", "")
            item = STORE.peek(token)
            if not item:
                return self._json({"error": "文件不存在或已过期"}, 404)
            data = item["data"]
            name = item["name"]
            STORE.pop(token)
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Disposition", _content_disposition(name))
            self.send_header("Content-Length", len(data))
            self.send_header("Connection", "close")
            self.close_connection = True
            self.end_headers()
            self.wfile.write(data)
            return

        self.send_error(404)

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path == "/api/config":
            patch = self._parse_json()
            if not patch:
                return self._json({"error": "无效的请求体"}, 400)
            data = CONFIG.update(patch)
            return self._json({"config": data})

        if path == "/api/explore":
            body = self._parse_json()
            d = body.get("dir", "")
            recursive = body.get("recursive", False)
            if not d:
                d = str(PROJECT_ROOT)
            result = _explore(Path(d), recursive)
            return self._json(result)

        if path == "/api/scan":
            body = self._parse_json()
            d = body.get("dir", "")
            recursive = body.get("recursive", False)
            if not d:
                d = str(PROJECT_ROOT)
            files = _scan_dir(Path(d), recursive)
            return self._json({"files": files})

        if path == "/api/jobs":
            body = self._parse_json()
            items = body.get("items", [])
            opts = body.get("opts", {})
            name = body.get("name", "")
            if not items:
                return self._json({"error": "没有选择文件"}, 400)
            cfg = CONFIG.get()
            merged = {**cfg, **opts}
            jid = JOBS.add(Job(None, items, merged, name))
            return self._json({"id": jid})

        if path == "/api/jobs/stop":
            body = self._parse_json()
            jid = body.get("id", "")
            ok = JOBS.stop(jid)
            return self._json({"ok": ok})

        if path == "/api/jobs/delete":
            body = self._parse_json()
            jid = body.get("id", "")
            ok = JOBS.delete(jid)
            return self._json({"ok": ok})

        if path == "/api/jobs/delete-all":
            count = JOBS.delete_all()
            return self._json({"deleted": count})

        if path == "/api/upload":
            return self._handle_upload()

        if path == "/api/kgg/upload":
            return self._handle_kgg_upload()

        if path == "/api/output/delete":
            body = self._parse_json()
            names = body.get("names") or body.get("files") or []
            base = _output_dir().resolve()
            deleted = 0
            for n in names:
                try:
                    p = (base / str(n)).resolve()
                    p.relative_to(base)
                except (ValueError, OSError):
                    continue
                try:
                    if p.is_file():
                        p.unlink()
                        deleted += 1
                except OSError:
                    pass
            return self._json({"deleted": deleted})

        if path == "/api/output/copy":
            body = self._parse_json()
            names = body.get("names") or body.get("files") or []
            dest = body.get("dest", "")
            if not dest:
                return self._json({"error": "缺少目标目录"}, 400)
            try:
                dest_dir = Path(dest).expanduser()
                dest_dir.mkdir(parents=True, exist_ok=True)
            except OSError as e:
                return self._json({"error": f"无法创建目标目录: {e}"}, 400)
            base = _output_dir().resolve()
            copied = 0
            for n in names:
                try:
                    p = (base / str(n)).resolve()
                    p.relative_to(base)
                except (ValueError, OSError):
                    continue
                if not p.is_file():
                    continue
                try:
                    target = dest_dir / p.name
                    if target.exists():
                        stem, suffix = p.stem, p.suffix
                        i = 1
                        while target.exists():
                            target = dest_dir / f"{stem} ({i}){suffix}"
                            i += 1
                    shutil.copy2(p, target)
                    copied += 1
                except OSError:
                    pass
            return self._json({"copied": copied, "dest": str(dest_dir)})

        self.send_error(404)

    def _handle_upload(self):
        """Handle multipart file upload for device-side decryption."""
        content_type = self.headers.get("Content-Type", "")
        if "multipart/form-data" not in content_type:
            return self._json({"error": "需要 multipart/form-data"}, 400)

        boundary = ""
        for part in content_type.split(";"):
            part = part.strip()
            if part.startswith("boundary="):
                boundary = part[9:]
        if not boundary:
            return self._json({"error": "缺少 boundary"}, 400)

        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)

        parts = self._parse_multipart(body, boundary)
        results = []
        for fname, fdata in parts:
            if not fname or not fdata:
                continue
            ext = Path(fname).suffix
            try:
                result = decrypt_bytes(fdata, ext)
                out_ext = sniff_audio(result.data) or result.ext or ""
                out_name = result.clean_name(fname) + out_ext
                token = STORE.put({
                    "data": result.data,
                    "name": out_name,
                    "ext": out_ext,
                    "title": result.title,
                    "original": fname,
                })
                results.append({
                    "token": token,
                    "name": out_name,
                    "ext": out_ext,
                    "size": len(result.data),
                    "title": result.title,
                })
            except DecryptError as e:
                results.append({"name": fname, "error": str(e)})
            except Exception as e:
                results.append({"name": fname, "error": str(e)})
        return self._json({"results": results})

    def _handle_kgg_upload(self):
        """Upload KGMusicV3.db 或 kgg.key，解密后缓存并加载酷狗密钥映射。"""
        content_type = self.headers.get("Content-Type", "")
        if "multipart/form-data" not in content_type:
            return self._json({"error": "需要 multipart/form-data"}, 400)

        boundary = ""
        for part in content_type.split(";"):
            part = part.strip()
            if part.startswith("boundary="):
                boundary = part[9:]
        if not boundary:
            return self._json({"error": "缺少 boundary"}, 400)

        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        parts = self._parse_multipart(body, boundary)

        results = []
        BASE_DIR.mkdir(parents=True, exist_ok=True)
        for fname, fdata in parts:
            if not fname or not fdata:
                continue
            low = fname.lower()
            try:
                if low.endswith(".db"):
                    KGG_DB_CACHE.write_bytes(fdata)
                    n = kgg_keys.configure(db_path=str(KGG_DB_CACHE))
                    CONFIG.update({"kgg_db": str(KGG_DB_CACHE)})
                    log(f"酷狗密钥库上传成功: {len(fdata)} bytes, {n} 条映射")
                    results.append({
                        "name": fname, "loaded": True, "type": "db",
                        "count": n, "source": kgg_keys.source(),
                    })
                elif low.endswith(".key") or low.endswith(".kgg.key"):
                    KGG_KEY_CACHE.write_bytes(fdata)
                    n = kgg_keys.configure(key_path=str(KGG_KEY_CACHE))
                    CONFIG.update({"kgg_key": str(KGG_KEY_CACHE)})
                    log(f"kgg.key 上传成功: {n} 条映射")
                    results.append({
                        "name": fname, "loaded": True, "type": "key",
                        "count": n, "source": kgg_keys.source(),
                    })
                else:
                    results.append({"name": fname, "error": "仅支持 .db 或 .key 文件"})
            except kgg_keys.KggKeyError as e:
                results.append({
                    "name": fname, "error": str(e),
                    "hint": getattr(e, "hint", ""),
                })
            except OSError as e:
                results.append({"name": fname, "error": f"保存失败: {e}"})
        return self._json({"results": results})

    def _parse_multipart(self, body: bytes, boundary: str) -> list[tuple[str, bytes]]:
        """Simple multipart parser for file uploads."""
        sep = ("--" + boundary).encode()
        end = ("--" + boundary + "--").encode()
        parts = []
        idx = body.find(sep)
        while idx >= 0:
            next_idx = body.find(sep, idx + len(sep))
            chunk = body[idx + len(sep):next_idx] if next_idx >= 0 else body[idx + len(sep):]
            if chunk.endswith(end):
                chunk = chunk[:-(len(end) + 2)]
            header_end = chunk.find(b"\r\n\r\n")
            if header_end < 0:
                idx = next_idx
                continue
            headers_raw = chunk[:header_end].decode("utf-8", errors="replace")
            data = chunk[header_end + 4:]
            if data.endswith(b"\r\n"):
                data = data[:-2]
            fname = ""
            for line in headers_raw.split("\r\n"):
                if "filename=" in line:
                    fn_part = line.split("filename=")[-1].strip('"')
                    fname = fn_part
            if fname:
                parts.append((fname, data))
            idx = next_idx
        return parts


def start_server(host: str, port: int, background: bool = False, open_browser: bool = False):
    """Start the HTTP server."""
    server = ThreadingHTTPServer((host, port), Handler)
    display_host = "127.0.0.1" if host in ("0.0.0.0", "::") else host
    log(f"服务启动: http://{display_host}:{port}")
    if open_browser:
        threading.Timer(1.0, lambda: webbrowser.open(f"http://{display_host}:{port}")).start()
    if background:
        _daemonize()

    def _purge_loop():
        while True:
            time.sleep(60)
            try:
                STORE.purge()
            except Exception:
                pass

    threading.Thread(target=_purge_loop, daemon=True).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log("服务已停止")
        server.server_close()


def _daemonize():
    """Fork to background (Unix)."""
    pid = os.fork()
    if pid > 0:
        print(f"守护进程已启动, PID: {pid}")
        os._exit(0)
    os.setsid()
    BASE_DIR.mkdir(parents=True, exist_ok=True)
    PID_PATH.write_text(str(os.getpid()), "utf-8")
    log_fd = open(LOG_PATH, "a")
    os.dup2(log_fd.fileno(), 1)
    os.dup2(log_fd.fileno(), 2)


def _stop_service():
    """Stop the running daemon."""
    if not PID_PATH.exists():
        print("服务未运行")
        return
    try:
        pid = int(PID_PATH.read_text("utf-8").strip())
        os.kill(pid, 15)
        print(f"已发送停止信号到 PID {pid}")
    except (ValueError, ProcessLookupError):
        print("进程不存在")
    PID_PATH.unlink(missing_ok=True)


def _status_service():
    """Check service status."""
    if not PID_PATH.exists():
        print("服务未运行")
        return
    try:
        pid = int(PID_PATH.read_text("utf-8").strip())
        os.kill(pid, 0)
        print(f"服务运行中, PID: {pid}")
    except (ValueError, ProcessLookupError):
        print("服务未运行 (残留 PID 文件)")
        PID_PATH.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description="音乐解锁后台服务")
    parser.add_argument("--daemon", action="store_true", help="后台守护进程运行")
    parser.add_argument("--stop", action="store_true", help="停止后台服务")
    parser.add_argument("--status", action="store_true", help="查看服务状态")
    parser.add_argument("--open", action="store_true", help="启动后自动打开浏览器")
    parser.add_argument("--port", type=int, help="覆盖配置文件端口")
    parser.add_argument("--host", type=str, help="覆盖配置文件地址")
    args = parser.parse_args()

    if args.stop:
        return _stop_service()
    if args.status:
        return _status_service()

    cfg = CONFIG.get()
    host = args.host or cfg.get("host", "127.0.0.1")
    port = args.port or cfg.get("port", 8765)

    _load_kgg_from_config()

    if args.daemon:
        start_server(host, port, background=True)
    else:
        start_server(host, port, background=False, open_browser=args.open)


if __name__ == "__main__":
    main()


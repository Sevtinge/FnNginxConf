#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FnNginxConf - unix socket HTTP 服务（统一网关接入）

- 监听统一网关声明的 unix socket（${TRIM_APPDEST}/app.sock）；本地预览可用 PORT 回退 TCP
- 网关转发带完整前缀路径（/app/FnNginxConf/...），本服务自动剥离
- 提供 REST API（规则 CRUD / apply / status）与静态前端页面
- 写接口按 X-Trim-Isadmin 管理员门禁（TCP 预览模式视为管理员）
"""

import http.server
import json
import os
import re
import socketserver
import sys
import threading
import time
import uuid

import nginx_cfg
import rules as rules_mod

# ---------------------------------------------------------------------------
# 配置项（由 cmd/main 通过环境变量注入）
# ---------------------------------------------------------------------------

LOG_FILE = os.environ.get("LOG_FILE", "/var/apps/FnNginxConf/var/app.log")
SOCK_PATH = os.environ.get("SOCK_PATH", "")          # unix socket（网关代理用）
PORT = os.environ.get("PORT", "").strip()            # 非空时回退 TCP 本地预览
GATEWAY_PREFIX = os.environ.get("GATEWAY_PREFIX", "/app/FnNginxConf")
RULES_FILE = os.environ.get("RULES_FILE", "/var/apps/FnNginxConf/var/rules.json")
APPLIED_FILE = os.path.join(os.path.dirname(RULES_FILE), "applied.json")

WEB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web")
MAX_BODY_BYTES = 256 * 1024
MAX_RULES = 200   # 规则数量上限，防止 conf 文件无界增长

PREVIEW_MODE = False   # 本地 TCP 预览时视为管理员
_applying = False      # 后台是否正在应用配置（防并发 + 前端 busy 状态）

try:
    _manifest_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "manifest")
    with open(_manifest_path, "r", encoding="utf-8") as _f:
        for _line in _f:
            if _line.strip().lower().startswith("version"):
                VERSION = _line.split("=", 1)[1].strip().strip("\"'") or "1.0.0"
                break
        else:
            VERSION = "1.0.0"
except Exception:
    VERSION = "1.0.0"

# ---------------------------------------------------------------------------
# 日志
# ---------------------------------------------------------------------------


def log(msg):
    line = "[%s] [server] %s\n" % (time.strftime("%Y-%m-%d %H:%M:%S"), msg)
    try:
        with open(LOG_FILE, "a", encoding="utf-8", errors="replace") as f:
            f.write(line)
    except Exception:
        print(line, end="")


# ---------------------------------------------------------------------------
# 静态资源缓存（注入 __APP_BASE__）
# ---------------------------------------------------------------------------

_index_cache = {"prefix": None, "data": None}


def _render_index():
    if _index_cache["data"] is not None and _index_cache["prefix"] == GATEWAY_PREFIX:
        return _index_cache["data"]
    try:
        with open(os.path.join(WEB_DIR, "index.html"), "r", encoding="utf-8") as f:
            html = f.read()
    except OSError:
        return None
    html = html.replace("__APP_BASE__", GATEWAY_PREFIX)
    _index_cache.update(prefix=GATEWAY_PREFIX, data=html)
    return html


# ---------------------------------------------------------------------------
# HTTP Handler
# ---------------------------------------------------------------------------

MIME = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".png": "image/png",
    ".svg": "image/svg+xml",
    ".ico": "image/x-icon",
    ".map": "application/json",
    ".txt": "text/plain; charset=utf-8",
}

_RULES_ID_RE = re.compile(r"^/api/rules/([0-9a-f]{32})$")


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        log("%s - %s" % (self.address_string(), fmt % args))

    def address_string(self):
        # unix socket 下 client_address 是路径字符串而非 (host, port), 需兼容
        addr = getattr(self, "client_address", None)
        if isinstance(addr, tuple):
            return super().address_string()
        return str(addr) if addr else "-"

    # ---------- 基础设施 ----------

    def _strip_prefix(self, path):
        """剥离网关前缀（带 / 不带都兼容），非前缀路径原样返回。"""
        if not GATEWAY_PREFIX:
            return path
        if path == GATEWAY_PREFIX:
            return "/"
        if path.startswith(GATEWAY_PREFIX + "/"):
            return path[len(GATEWAY_PREFIX):]
        return path

    def _is_admin(self):
        if PREVIEW_MODE:
            return True
        return self.headers.get("X-Trim-Isadmin", "").strip().lower() == "true"

    def _read_json(self):
        raw_len = self.headers.get("Content-Length")
        try:
            length = int(raw_len) if raw_len else 0
        except ValueError:
            return None, 400, "无效的 Content-Length"
        if length <= 0 or length > MAX_BODY_BYTES:
            return None, 400, "请求体为空或过大"
        try:
            body = self.rfile.read(length)
        except OSError:
            return None, 400, "读取请求体失败"
        try:
            payload = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            return None, 400, "JSON 解析失败"
        if not isinstance(payload, dict):
            return None, 400, "请求体必须是 JSON 对象"
        return payload, 0, None

    def _send(self, status, obj, content_type="application/json; charset=utf-8"):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _ok(self, data=None):
        self._send(200, {"code": 0, "msg": "", "data": data})

    def _err(self, status, msg, data=None):
        self._send(status, {"code": status, "msg": msg, "data": data})

    # ---------- 路由 ----------

    def _handle(self):
        path = self._strip_prefix(urlsplit_path(self.path))
        method = self.command

        # 静态资源
        if method == "GET" and not path.startswith("/api/"):
            self._serve_static(path)
            return

        # API
        if method == "GET" and path == "/api/status":
            self._api_status()
            return
        if method == "GET" and path == "/api/rules":
            self._ok({"rules": rules_mod.load_rules()})
            return
        if method == "POST" and path == "/api/check-location":
            self._api_check_location()
            return
        if method == "POST" and path == "/api/rules":
            self._api_create_rule()
            return
        if method == "POST" and path == "/api/apply":
            self._api_apply()
            return
        if method == "POST" and path == "/api/nginx/reload":
            self._api_reload()
            return
        m = _RULES_ID_RE.match(path)
        if m and method == "PUT":
            self._api_update_rule(m.group(1))
            return
        if m and method == "DELETE":
            self._api_delete_rule(m.group(1))
            return
        self._err(404, "not found")

    # ---------- 静态资源 ----------

    def _serve_static(self, path):
        if path in ("/", "/index.html"):
            html = _render_index()
            if html is None:
                self._err(404, "index.html 缺失")
                return
            body = html.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", MIME[".html"])
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            self.wfile.write(body)
            return

        rel = path.lstrip("/")
        # 目录穿越防护
        if not rel or rel.startswith("..") or "/.." in "/" + rel:
            self._err(400, "bad path")
            return
        target = os.path.normpath(os.path.join(WEB_DIR, rel))
        if not target.startswith(WEB_DIR) or not os.path.isfile(target):
            self._err(404, "not found")
            return
        ext = os.path.splitext(target)[1].lower()
        try:
            with open(target, "rb") as f:
                data = f.read()
        except OSError:
            self._err(500, "read failed")
            return
        self.send_response(200)
        self.send_header("Content-Type", MIME.get(ext, "application/octet-stream"))
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    # ---------- API ----------

    def _api_status(self):
        current = rules_mod.load_rules()
        h = rules_mod.rules_hash(current)
        applied = {}
        try:
            with open(APPLIED_FILE, "r", encoding="utf-8") as f:
                applied = json.load(f)
        except (OSError, ValueError):
            applied = {}
        self._ok({
            "admin": self._is_admin(),
            "prefix": GATEWAY_PREFIX,
            "version": VERSION,
            "rules": len(current),
            "applied": applied.get("rulesHash") == h,
            "busy": _applying,
            "lastApplyAt": applied.get("at"),
            "lastApplyResult": applied.get("result"),
            "lastApplyMessage": applied.get("message"),
            "lastApplyDetail": applied.get("detail"),
            "nginxActive": nginx_cfg.nginx_active(),
        })

    def _api_check_location(self):
        payload, code, err = self._read_json()
        if code != 0:
            self._err(code, err)
            return
        status, msg, detail = nginx_cfg.check_location_conflict(payload.get("location", ""))
        self._ok({"status": status, "message": msg, "detail": detail})

    def _require_admin(self):
        if not self._is_admin():
            self._err(403, "仅管理员可修改配置")
            return False
        return True

    def _api_create_rule(self):
        if not self._require_admin():
            return
        payload, code, err = self._read_json()
        if code != 0:
            self._err(code, err)
            return
        existing = rules_mod.load_rules()
        if len(existing) >= MAX_RULES:
            self._err(400, "规则数量已达上限（%d 条）" % MAX_RULES)
            return
        rule, verr, warning = rules_mod.validate_rule(payload, existing=existing)
        if verr:
            self._err(400, verr)
            return
        existing.append(rule)
        if not rules_mod.save_rules(existing):
            self._err(500, "保存规则失败")
            return
        self._ok({"rule": rule, "warning": warning})

    def _api_update_rule(self, rid):
        if not self._require_admin():
            return
        payload, code, err = self._read_json()
        if code != 0:
            self._err(code, err)
            return
        existing = rules_mod.load_rules()
        idx = next((i for i, r in enumerate(existing) if r.get("id") == rid), None)
        if idx is None:
            self._err(404, "规则不存在")
            return
        merged = dict(existing[idx])
        merged.update({k: v for k, v in payload.items() if k != "id"})
        rule, verr, warning = rules_mod.validate_rule(merged, existing=existing, exclude_id=rid)
        if verr:
            self._err(400, verr)
            return
        existing[idx] = rule
        if not rules_mod.save_rules(existing):
            self._err(500, "保存规则失败")
            return
        self._ok({"rule": rule, "warning": warning})

    def _api_delete_rule(self, rid):
        if not self._require_admin():
            return
        existing = rules_mod.load_rules()
        nxt = [r for r in existing if r.get("id") != rid]
        if len(nxt) == len(existing):
            self._err(404, "规则不存在")
            return
        if not rules_mod.save_rules(nxt):
            self._err(500, "保存规则失败")
            return
        self._ok({"deleted": rid})

    def _save_applied(self, rules, ok, message, detail):
        try:
            with open(APPLIED_FILE, "w", encoding="utf-8", newline="\n") as f:
                json.dump({
                    "rulesHash": rules_mod.rules_hash(rules),
                    "at": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "result": ok,
                    "message": message,
                    "detail": detail or "",
                }, f, ensure_ascii=False, indent=2)
        except OSError as e:
            log("写 applied.json 失败: %s" % e)

    def _api_apply(self):
        if not self._require_admin():
            return
        global _applying
        if _applying:
            self._err(409, "正在应用中，请稍候再试。")
            return
        _applying = True
        rules = rules_mod.load_rules()
        # 立即返回，重活在后台线程执行——网关即 nginx，任何耗时/重启都会切断本请求连接
        # （浏览器报 Failed to fetch）。响应毫秒级送达后再做真正的工作。
        self._ok({"message": "应用已提交，正在后台执行…", "busy": True})
        threading.Thread(target=self._apply_worker, args=(rules,), daemon=True).start()

    def _apply_worker(self, rules):
        global _applying
        try:
            ok, message, detail, changed = nginx_cfg.prepare(rules)
            self._save_applied(rules, ok, message, detail)
            if not ok:
                return
            if changed:
                time.sleep(1.0)   # 确保提交响应已送达浏览器
                rok, rdetail = nginx_cfg.restart_nginx()
                if not rok:
                    log("nginx 重启失败: %s" % rdetail)
                    self._save_applied(rules, False,
                                       "配置已写入，但 nginx 重启失败，尚未生效。", rdetail)
        except Exception as e:
            log("apply 后台执行异常: %r" % (e,))
            self._save_applied(rules, False, "应用配置异常", repr(e))
        finally:
            _applying = False

    def _api_reload(self):
        if not self._require_admin():
            return
        self._ok({"message": "nginx 正在后台重启…", "busy": True})
        threading.Thread(target=self._restart_worker, daemon=True).start()

    def _restart_worker(self):
        time.sleep(0.5)
        try:
            ok, detail = nginx_cfg.restart_nginx()
            if not ok:
                log("nginx 重启失败: %s" % detail)
        except Exception as e:
            log("nginx 重启异常: %r" % (e,))

    # ---------- 兜底 ----------

    def _safe(self, fn):
        try:
            fn()
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as e:
            log("未处理异常: %r" % (e,))
            try:
                self._err(500, "internal error")
            except Exception:
                pass

    def do_GET(self):
        self._safe(self._handle)

    def do_POST(self):
        self._safe(self._handle)

    def do_PUT(self):
        self._safe(self._handle)

    def do_DELETE(self):
        self._safe(self._handle)


def urlsplit_path(raw):
    """取 URL 的 path 部分（去 query/fragment）。"""
    i = raw.find("?")
    if i < 0:
        i = raw.find("#")
    if i < 0:
        return raw
    return raw[:i]


# ---------------------------------------------------------------------------
# 服务器
# ---------------------------------------------------------------------------

# UnixStreamServer 仅在类 Unix 平台可用（Windows 本地预览时退化为 TCP）
ThreadingUnixHTTPServer = None
if hasattr(socketserver, "UnixStreamServer"):

    class ThreadingUnixHTTPServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
        daemon_threads = True
        allow_reuse_address = True


class ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def main():
    global PREVIEW_MODE
    nginx_cfg.ensure(rules_mod.load_rules())

    sock = os.environ.get("SOCK_PATH", "")
    port = os.environ.get("PORT", "").strip()

    if sock:
        if ThreadingUnixHTTPServer is None:
            log("当前平台不支持 unix socket（本地预览请改用 PORT 环境变量）")
            return 1
        if os.path.exists(sock):
            try:
                os.unlink(sock)          # 清理上次遗留的 socket 文件
            except OSError:
                pass
        try:
            srv = ThreadingUnixHTTPServer(sock, Handler)
            os.chmod(sock, 0o666)        # 让网关服务用户能连接
        except Exception as e:
            log("unix socket 启动失败: %s" % e)
            return 1
        log("服务启动，监听 unix socket %s" % sock)
    elif port:
        try:
            p = int(port)
        except ValueError:
            log("PORT 非法: %s" % port)
            return 1
        PREVIEW_MODE = True
        try:
            srv = ThreadingHTTPServer(("127.0.0.1", p), Handler)
        except Exception as e:
            log("TCP 预览启动失败: %s" % e)
            return 1
        log("服务启动，监听 http://127.0.0.1:%d（本地预览）" % p)
    else:
        log("未配置 SOCK_PATH 或 PORT，无法监听")
        return 1

    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())

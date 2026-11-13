#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Local Portfolio Visual Editor Server (/api/save)

Phục vụ trang web và ghi file Final sạch vào thư mục Git khi bấm [Lưu file sạch (Final)].

Bảo vệ endpoint ghi file (F10):
  * Chỉ bind loopback; kiểm tra header Host (chặn DNS rebinding).
  * Không còn CORS "*": trang ngoài origin không đọc được token và không gọi được /api/save.
  * Token phiên ngẫu nhiên (secrets.token_urlsafe) cấp qua GET /api/session cho đúng same-origin
    (Sec-Fetch-Site / Origin / Referer phải khớp dev origin); POST bắt buộc header X-W17-Token.
  * Bắt buộc Content-Type: application/json, giới hạn kích thước body, chỉ ghi allowlist tên file.
  * Kiểm tra cấu trúc HTML trước khi ghi; ghi nguyên tử (tệp tạm + os.replace) và backup bản cũ.
  * Trả đúng trạng thái: 200 chỉ khi mọi target đã ghi; 4xx/5xx kèm lý do nếu không.
"""

import hmac
import json
import os
import re
import secrets
import tempfile
import time
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

BASE_DIR = Path(os.environ.get("W17_BASE_DIR") or Path(__file__).resolve().parent).resolve()
BACKUP_DIR_NAME = ".w17_backups"
BACKUP_KEEP = 5
MAX_BODY_BYTES = 12 * 1024 * 1024  # file Final ~0.3MB; chừa chỗ cho ảnh đại diện base64

# filename -> (marker bắt buộc phải có trong HTML hợp lệ, tên hiển thị)
ALLOWED_FILES = {
    "index.html": 'id="ga4-ecosystem"',
    "index_portfolio_clean.html": 'id="portfolio-root"',
}

# Không phục vụ mã nguồn server, dữ liệu nhạy cảm hoặc thư mục ẩn qua HTTP.
BLOCKED_SUFFIXES = (".py", ".pyc", ".env", ".log")
BLOCKED_PREFIXES = ("service_account", "credentials")

SESSION_TOKEN = secrets.token_urlsafe(32)


def allowed_hosts(port):
    return {f"127.0.0.1:{port}", f"localhost:{port}"}


def allowed_origins(port):
    return {f"http://127.0.0.1:{port}", f"http://localhost:{port}"}


class SaveError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status
        self.message = message


def validate_html(filename, html):
    if not isinstance(html, str) or not html.strip():
        raise SaveError(400, "Nội dung HTML rỗng hoặc không phải chuỗi.")
    head = html.lstrip()[:200].lower()
    if not (head.startswith("<!doctype html") or head.startswith("<html")):
        raise SaveError(422, "Nội dung không bắt đầu bằng <!DOCTYPE html> hoặc <html>.")
    if "</html>" not in html[-400:].lower():
        raise SaveError(422, "Nội dung HTML không kết thúc bằng </html> (có thể bị cắt cụt).")
    marker = ALLOWED_FILES[filename]
    if marker not in html:
        raise SaveError(422, f"HTML không phải bản của {filename} (thiếu {marker}).")
    static_html = re.sub(r"<script\b.*?</script>", "", html, flags=re.S | re.I)
    if re.search(r"""id=["'](?:visual|floating)-toolbar["']|\scontenteditable\s*=""", static_html):
        raise SaveError(422, "Bản Final còn thanh công cụ editor hoặc contenteditable trong HTML tĩnh; từ chối ghi.")


def backup_existing(target):
    if not target.exists():
        return None
    backup_dir = BASE_DIR / BACKUP_DIR_NAME
    backup_dir.mkdir(exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    backup_path = backup_dir / f"{target.name}.{stamp}.bak"
    counter = 1
    while backup_path.exists():
        backup_path = backup_dir / f"{target.name}.{stamp}-{counter}.bak"
        counter += 1
    backup_path.write_bytes(target.read_bytes())
    old = sorted(backup_dir.glob(f"{target.name}.*.bak"), key=lambda p: p.stat().st_mtime)
    for stale in old[:-BACKUP_KEEP]:
        try:
            stale.unlink()
        except OSError:
            pass
    return backup_path


def atomic_write(target, text):
    fd, tmp_name = tempfile.mkstemp(prefix=target.name + ".", suffix=".tmp", dir=str(target.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, target)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


class PortfolioEditorHandler(SimpleHTTPRequestHandler):
    server_version = "W17Editor/1.0"
    sys_version = ""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(BASE_DIR), **kwargs)

    # ---- helpers -------------------------------------------------------------
    @property
    def _port(self):
        return self.server.server_address[1]

    def _host_ok(self):
        return (self.headers.get("Host") or "") in allowed_hosts(self._port)

    def _same_origin_ok(self):
        origin = self.headers.get("Origin")
        if origin is not None:
            return origin in allowed_origins(self._port)
        site = self.headers.get("Sec-Fetch-Site")
        if site is not None:
            return site in ("same-origin", "none")
        referer = self.headers.get("Referer")
        if referer:
            parts = urlsplit(referer)
            return f"{parts.scheme}://{parts.netloc}" in allowed_origins(self._port)
        return False

    def _send_json(self, status, payload):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def end_headers(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        super().end_headers()

    # ---- static --------------------------------------------------------------
    def _path_blocked(self):
        path = urlsplit(self.path).path
        segments = [s for s in path.split("/") if s]
        if any(s.startswith(".") for s in segments):
            return True
        if not segments:
            return False
        last = segments[-1].lower()
        return last.endswith(BLOCKED_SUFFIXES) or last.startswith(BLOCKED_PREFIXES)

    def do_GET(self):
        if not self._host_ok():
            self._send_json(403, {"status": "error", "message": "Host không được phép."})
            return
        path = urlsplit(self.path).path
        if path == "/api/session":
            if not self._same_origin_ok():
                self._send_json(403, {"status": "error", "message": "Chỉ trang cùng origin mới lấy được token."})
                return
            self._send_json(200, {"status": "ok", "token": SESSION_TOKEN, "files": sorted(ALLOWED_FILES)})
            return
        if self._path_blocked():
            self._send_json(404, {"status": "error", "message": "Không tìm thấy."})
            return
        super().do_GET()

    def do_HEAD(self):
        if not self._host_ok() or self._path_blocked():
            self.send_response(404)
            self.end_headers()
            return
        super().do_HEAD()

    def do_OPTIONS(self):
        # Không cấp CORS: preflight từ origin khác không nhận Access-Control-Allow-*.
        self.send_response(405)
        self.send_header("Allow", "GET, HEAD, POST")
        self.send_header("Content-Length", "0")
        self.end_headers()

    # ---- save ----------------------------------------------------------------
    def _discard_unread_body(self):
        """Từ chối sớm mà không đọc body dễ làm TCP gửi RST, client không nhận được mã lỗi: đọc bỏ body nhỏ, đóng kết nối nếu lớn."""
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if getattr(self, "_body_consumed", False) or length <= 0:
            return
        if length <= 1024 * 1024:
            self.rfile.read(length)
        else:
            self.close_connection = True

    def do_POST(self):
        self._body_consumed = False
        if urlsplit(self.path).path != "/api/save":
            self._discard_unread_body()
            self._send_json(404, {"status": "error", "message": "Không tìm thấy endpoint."})
            return
        try:
            if not self._host_ok():
                raise SaveError(403, "Host không được phép.")
            if not self._same_origin_ok():
                raise SaveError(403, "Origin không được phép.")
            supplied = self.headers.get("X-W17-Token") or ""
            if not hmac.compare_digest(supplied.encode("utf-8"), SESSION_TOKEN.encode("utf-8")):
                raise SaveError(401, "Thiếu hoặc sai token phiên. Tải lại trang editor rồi lưu lại.")
            ctype = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
            if ctype != "application/json":
                raise SaveError(415, "Content-Type phải là application/json.")
            try:
                length = int(self.headers.get("Content-Length") or "")
            except ValueError:
                raise SaveError(411, "Thiếu Content-Length hợp lệ.")
            if length <= 0:
                raise SaveError(400, "Body rỗng.")
            if length > MAX_BODY_BYTES:
                raise SaveError(413, f"Body vượt giới hạn {MAX_BODY_BYTES // (1024 * 1024)}MB.")
            raw = self.rfile.read(length)
            self._body_consumed = True
            if len(raw) != length:
                raise SaveError(400, "Body bị cắt cụt.")
            try:
                data = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                raise SaveError(400, "Body không phải JSON UTF-8 hợp lệ.")
            if not isinstance(data, dict):
                raise SaveError(400, "Body JSON phải là object.")

            html = data.get("html")
            targets = data.get("targets")
            if targets is None:
                targets = [data.get("filename")]
            if not isinstance(targets, list) or not targets or len(targets) > len(ALLOWED_FILES):
                raise SaveError(400, "Danh sách targets không hợp lệ.")
            if any(not isinstance(t, str) or t not in ALLOWED_FILES for t in targets):
                raise SaveError(400, "Tên file không nằm trong allowlist: " + ", ".join(sorted(ALLOWED_FILES)))
            targets = list(dict.fromkeys(targets))
            for name in targets:
                validate_html(name, html)

            saved, backups = [], []
            for name in targets:
                target = BASE_DIR / name
                backup = backup_existing(target)
                atomic_write(target, html)
                saved.append(name)
                if backup is not None:
                    backups.append(backup.name)
            self._send_json(200, {"status": "ok", "saved": saved, "backups": backups, "bytes": len(html.encode("utf-8"))})
        except SaveError as err:
            self._discard_unread_body()
            self._send_json(err.status, {"status": "error", "saved": [], "message": err.message})
        except OSError as err:
            self._send_json(500, {"status": "error", "saved": [], "message": f"Không ghi được file: {err.strerror or err}"})
        except Exception:
            self._send_json(500, {"status": "error", "saved": [], "message": "Lỗi nội bộ khi lưu file."})

    def log_message(self, fmt, *args):
        super().log_message(fmt, *args)


def make_server(port):
    return ThreadingHTTPServer(("127.0.0.1", port), PortfolioEditorHandler)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8000"))
    server = make_server(port)
    print(f"Portfolio Editor Server running at http://127.0.0.1:{port}  (token phiên được cấp tự động cho trang cùng origin)")
    server.serve_forever()

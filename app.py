# app.py
import os
import time
import secrets
from functools import wraps
from urllib.parse import urljoin, urlparse, quote, unquote

from flask import (
    Flask, request, render_template, Response, redirect, abort, session, make_response
)
import requests
from bs4 import BeautifulSoup
from werkzeug.middleware.proxy_fix import ProxyFix
from collections import defaultdict

# --- 設定（環境変数で上書き可能） ---
PORT = int(os.environ.get("PORT", 8080))
BASIC_USER = os.environ.get("BASIC_USER")   # set on Render
BASIC_PASS = os.environ.get("BASIC_PASS")
ALLOW_HOSTS = os.environ.get("ALLOW_HOSTS")  # カンマ区切りでホワイトリスト（任意）
REQUEST_TIMEOUT = float(os.environ.get("REQUEST_TIMEOUT", "15"))
RATE_LIMIT_PER_MIN = int(os.environ.get("RATE_LIMIT_PER_MIN", "120"))

# 変更・追加: ブロック回避用ランダムパス
PROXY_PATH = os.environ.get("PROXY_PATH", "/" + secrets.token_hex(4))

# 変更・追加: デフォルトヘッダ偽装
DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                  "AppleWebKit/537.36 (KHTML, like Gecko) "
                  "Chrome/120.0.0.0 Safari/537.36",
    "Accept-Language": "ja,en-US;q=0.9,en;q=0.8",
}

app = Flask(__name__, static_folder=None)
app.wsgi_app = ProxyFix(app.wsgi_app)

visits = defaultdict(list)  # ip -> [timestamps]

def rate_limited(ip):
    now = time.time()
    window = 60
    timestamps = visits[ip]
    visits[ip] = [t for t in timestamps if now - t < window]
    if len(visits[ip]) >= RATE_LIMIT_PER_MIN:
        return True
    visits[ip].append(now)
    return False

def check_auth(u, p):
    if not (BASIC_USER and BASIC_PASS):
        return True
    return u == BASIC_USER and p == BASIC_PASS

def authenticate():
    resp = Response("Authentication required", 401)
    resp.headers['WWW-Authenticate'] = 'Basic realm="Proxy"'
    return resp

def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if auth:
            if check_auth(auth.username, auth.password):
                return f(*args, **kwargs)
        return authenticate()
    return decorated

def allowed_url(url):
    if not ALLOW_HOSTS:
        return True
    net = urlparse(url).netloc
    allowed = [h.strip().lower() for h in ALLOW_HOSTS.split(",") if h.strip()]
    return any(a in net for a in allowed)

def make_proxy_url(target):
    return PROXY_PATH + "?url=" + quote(target, safe='')

def is_html(resp):
    ct = resp.headers.get("content-type", "")
    return "text/html" in ct

def stream_response(resp):
    excluded = ["content-encoding", "transfer-encoding", "connection"]
    headers = [(k, v) for k, v in resp.raw.headers.items() if k.lower() not in excluded]
    return Response(resp.raw, status=resp.status_code, headers=dict(headers))

# -------------------------
# 追加: 静的/バイナリ資源中継
# -------------------------
@app.route("/asset")
def asset():
    raw_url = request.args.get("url")
    if not raw_url:
        return "missing url", 400
    raw_url = unquote(raw_url)
    try:
        upstream = requests.get(
            raw_url,
            stream=True,
            timeout=REQUEST_TIMEOUT,
            headers={"User-Agent": request.headers.get("User-Agent", DEFAULT_HEADERS["User-Agent"])}
        )
    except Exception as e:
        return f"upstream error: {e}", 502

    excluded = ["content-encoding", "transfer-encoding", "connection"]
    headers = {k: v for k, v in upstream.headers.items() if k.lower() not in excluded}
    return Response(upstream.raw, status=upstream.status_code, headers=headers)

def proxyify_url(u: str) -> str:
    if not u:
        return u
    lower = u.lower()
    if any(lower.endswith(ext) for ext in (
        ".js", ".css", ".png", ".jpg", ".jpeg", ".webp", ".gif", ".svg",
        ".woff", ".woff2", ".ttf", ".ico", ".otf", ".map", ".json", ".webmanifest"
    )):
        return "/asset?url=" + quote(u, safe='')
    return make_proxy_url(u)
# -------------------------
# 追加ここまで
# -------------------------

@app.route("/", methods=["GET", "POST"])
@requires_auth
def index():
    if rate_limited(request.remote_addr):
        return "Rate limit exceeded", 429
    if request.method == "POST":
        target = request.form.get("url", "")
        if not target:
            return redirect("/")
        if not target.startswith("http"):
            target = "http://" + target
        return redirect(make_proxy_url(target))
    return render_template("index.html")

# 変更: プロキシURLをランダム化
@app.route(PROXY_PATH, methods=["GET", "POST"])
@requires_auth
def proxy_alias():
    return proxy()

def proxy():
    if rate_limited(request.remote_addr):
        return "Rate limit exceeded", 429

    target = request.values.get("url")
    if not target:
        return "Missing url", 400
    target = unquote(target)

    if not allowed_url(target):
        return "Host not allowed", 403

    session_req = requests.Session()

    # 変更: ヘッダ偽装
    headers = DEFAULT_HEADERS.copy()
    for h in ["User-Agent", "Accept", "Accept-Language"]:
        if request.headers.get(h):
            headers[h] = request.headers[h]

    if request.cookies:
        session_req.cookies.update(request.cookies)

    method = request.method if request.method in ("GET", "POST") else "GET"
    try:
        if method == "POST":
            resp = session_req.request(
                "POST", target,
                headers=headers,
                data=request.form.to_dict(flat=True),
                allow_redirects=True,
                timeout=REQUEST_TIMEOUT,
                stream=True
            )
        else:
            resp = session_req.request(
                "GET", target,
                headers=headers,
                params=request.args.to_dict(flat=True) if request.args else None,
                allow_redirects=True,
                timeout=REQUEST_TIMEOUT,
                stream=True
            )
    except Exception as e:
        return f"Upstream request failed: {e}", 502

    if not is_html(resp):
        return stream_response(resp)

    body = resp.content
    soup = BeautifulSoup(body, "html.parser")

    for tag in soup.find_all(["a", "img", "link", "script", "form"]):
        if tag.name == "a" and tag.has_attr("href"):
            href = tag["href"]
            if href.startswith("javascript:") or href.startswith("mailto:") or href.startswith("#"):
                continue
            abs_url = urljoin(target, href)
            tag["href"] = proxyify_url(abs_url)
        elif tag.name in ["img", "script"] and tag.has_attr("src"):
            src = tag["src"]
            abs_url = urljoin(target, src)
            tag["src"] = proxyify_url(abs_url)
        elif tag.name == "link" and tag.has_attr("href"):
            href = tag["href"]
            abs_url = urljoin(target, href)
            tag["href"] = proxyify_url(abs_url)
        elif tag.name == "form":
            action = tag.get("action") or target
            abs_action = urljoin(target, action)
            tag["action"] = proxyify_url(abs_action)

    for base in soup.find_all("base"):
        base.decompose()

    res = make_response(str(soup))
    res.headers['Content-Type'] = resp.headers.get("content-type", "text/html; charset=utf-8")
    return res

@app.route("/_health")
def health():
    return "ok"

if __name__ == "__main__":
    app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-key")
    app.run(host="0.0.0.0", port=PORT, debug=False)

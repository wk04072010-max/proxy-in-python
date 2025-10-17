# app.py
import os
import time
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

app = Flask(__name__, static_folder=None)
app.wsgi_app = ProxyFix(app.wsgi_app)

# simple in-memory rate limiter (Render のスケールを考慮すると分散用の外部ストア推奨)
visits = defaultdict(list)  # ip -> [timestamps]

def rate_limited(ip):
    now = time.time()
    window = 60
    timestamps = visits[ip]
    # 古い記録を落とす
    visits[ip] = [t for t in timestamps if now - t < window]
    if len(visits[ip]) >= RATE_LIMIT_PER_MIN:
        return True
    visits[ip].append(now)
    return False

# Basic Auth
def check_auth(u, p):
    if not (BASIC_USER and BASIC_PASS):
        return True  # 環境変数未設定なら認証をスキップ（ただし運用では必ずセットして）
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

# ホストホワイトリスト検査（任意）
def allowed_url(url):
    if not ALLOW_HOSTS:
        return True
    net = urlparse(url).netloc
    allowed = [h.strip().lower() for h in ALLOW_HOSTS.split(",") if h.strip()]
    return any(a in net for a in allowed)

# Helpers
def make_proxy_url(target):
    return "/proxy?url=" + quote(target, safe='')

def is_html(resp):
    ct = resp.headers.get("content-type", "")
    return "text/html" in ct

def stream_response(resp):
    excluded = ["content-encoding", "transfer-encoding", "connection"]
    headers = [(k, v) for k, v in resp.raw.headers.items() if k.lower() not in excluded]
    return Response(resp.raw, status=resp.status_code, headers=dict(headers))

# -------------------------
# ここから追加：HTML連携用のエンドポイントとユーティリティ（既存コードは変更なし）
# -------------------------

@app.route("/asset")
def asset():
    """
    静的/バイナリ資源を中継するエンドポイント（画像/CSS/JSなど）
    使用例: <img src="/asset?url=https%3A%2F%2Fexample.com%2Fimage.png">
    """
    raw_url = request.args.get("url")
    if not raw_url:
        return "missing url", 400
    raw_url = unquote(raw_url)
    try:
        upstream = requests.get(
            raw_url,
            stream=True,
            timeout=REQUEST_TIMEOUT,
            headers={"User-Agent": request.headers.get("User-Agent", "Mozilla/5.0")}
        )
    except Exception as e:
        return f"upstream error: {e}", 502

    # ストリーミングでそのまま返す（Content-Type を維持）
    excluded = ["content-encoding", "transfer-encoding", "connection"]
    headers = {k: v for k, v in upstream.headers.items() if k.lower() not in excluded}
    return Response(upstream.raw, status=upstream.status_code, headers=headers)

def proxyify_url(u: str) -> str:
    """
    HTML内のリンクを /asset?url=... または /proxy?url=... に変換するためのユーティリティ
    資源の種類で簡易判定して振り分けます。
    """
    if not u:
        return u
    lower = u.lower()
    # 静的資源と判断できる拡張子は /asset へ
    if any(lower.endswith(ext) for ext in (
        ".js", ".css", ".png", ".jpg", ".jpeg", ".webp", ".gif", ".svg",
        ".woff", ".woff2", ".ttf", ".ico", ".otf", ".map", ".json", ".webmanifest"
    )):
        return "/asset?url=" + quote(u, safe='')
    return "/proxy?url=" + quote(u, safe='')

# 使用例コメント（/proxy 内の HTML 書き換えループでこう使えます）
# for tag in soup.find_all(["a","img","script","link","form"]):
#     if tag.name == "a" and tag.has_attr("href"):
#         href = urljoin(target, tag["href"])
#         tag["href"] = proxyify_url(href)
#     elif tag.name in ("img","script") and tag.has_attr("src"):
#         src = urljoin(target, tag["src"])
#         tag["src"] = proxyify_url(src)
#     elif tag.name == "link" and tag.has_attr("href"):
#         href = urljoin(target, tag["href"])
#         tag["href"] = proxyify_url(href)
#     elif tag.name == "form":
#         action = tag.get("action") or target
#         tag["action"] = "/proxy?url=" + quote(urljoin(target, action), safe='')

# -------------------------
# 追加ここまで
# -------------------------

# Routes
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

@app.route("/proxy", methods=["GET", "POST"])
@requires_auth
def proxy():
    if rate_limited(request.remote_addr):
        return "Rate limit exceeded", 429

    target = request.values.get("url")
    if not target:
        return "Missing url", 400
    target = unquote(target)

    if not allowed_url(target):
        return "Host not allowed", 403

    # handle POST and GET to target (form submission relay)
    session_req = requests.Session()

    # transfer some headers, but avoid sensitive ones
    headers = {}
    for h in ["User-Agent", "Accept", "Accept-Language"]:
        v = request.headers.get(h)
        if v:
            headers[h] = v

    # forward cookies from client if present (注意：セキュリティ上のリスクがある)
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

    # バイナリ/非HTMLはそのままストリーミング
    if not is_html(resp):
        return stream_response(resp)

    # HTML は解析してリンクを書き換える
    body = resp.content
    soup = BeautifulSoup(body, "html.parser")

    # 書き換え対象属性
    for tag in soup.find_all(["a", "img", "link", "script", "form"]):
        if tag.name == "a" and tag.has_attr("href"):
            href = tag["href"]
            # javascript: や mailto: は無視
            if href.startswith("javascript:") or href.startswith("mailto:") or href.startswith("#"):
                continue
            abs_url = urljoin(target, href)
            tag["href"] = make_proxy_url(abs_url)
        elif tag.name in ["img", "script"] and tag.has_attr("src"):
            src = tag["src"]
            abs_url = urljoin(target, src)
            tag["src"] = make_proxy_url(abs_url)
        elif tag.name == "link" and tag.has_attr("href"):
            href = tag["href"]
            abs_url = urljoin(target, href)
            tag["href"] = make_proxy_url(abs_url)
        elif tag.name == "form":
            # form の action をプロキシに差し替え
            action = tag.get("action") or target
            abs_action = urljoin(target, action)
            tag["action"] = make_proxy_url(abs_action)
            # method はそのまま残す

    # base タグがある場合は削除 or 上書きして混乱を避ける
    for base in soup.find_all("base"):
        base.decompose()

    # HTML を返す（元の content-type を維持）
    res = make_response(str(soup))
    res.headers['Content-Type'] = resp.headers.get("content-type", "text/html; charset=utf-8")
    return res

# simple healthcheck
@app.route("/_health")
def health():
    return "ok"

if __name__ == "__main__":
    # production では gunicorn を使う
    app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-key")
    app.run(host="0.0.0.0", port=PORT, debug=False)

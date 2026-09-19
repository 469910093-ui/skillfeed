#!/usr/bin/env bash
# 在阿里云轻量上把 FastAPI 挂到 127.0.0.1:8787，Nginx 反代登录/发布/API。
# 幂等。GitHub Client 先留空，填进 /opt/skill-feed/.env 后再 systemctl restart。
set -euo pipefail

ROOT=/opt/skill-feed
REPO="${SKILLFEED_REPO_URL:-https://github.com/469910093-ui/skillfeed.git}"

sudo mkdir -p "$ROOT"
sudo chown "$(id -un):$(id -gn)" "$ROOT"

if [ ! -d "$ROOT/.git" ]; then
  git clone "$REPO" "$ROOT"
else
  git -C "$ROOT" fetch --prune origin
  git -C "$ROOT" checkout main
  git -C "$ROOT" pull --ff-only origin main || true
fi

if ! python3 -c "import venv" 2>/dev/null; then
  sudo apt-get update -y
  sudo apt-get install -y python3-venv python3-pip
fi

if [ ! -x "$ROOT/.venv/bin/python" ]; then
  python3 -m venv "$ROOT/.venv"
fi
"$ROOT/.venv/bin/pip" install -q --upgrade pip -i https://mirrors.aliyun.com/pypi/simple/ --trusted-host mirrors.aliyun.com
"$ROOT/.venv/bin/pip" install -q -r "$ROOT/requirements-server.txt" -i https://mirrors.aliyun.com/pypi/simple/ --trusted-host mirrors.aliyun.com

if [ ! -f "$ROOT/.env" ]; then
  secret="$("$ROOT/.venv/bin/python" -c 'import secrets;print(secrets.token_urlsafe(32))')"
  cat > "$ROOT/.env" <<EOF
SKILLFEED_PUBLIC_URL=https://skillfeeder.cn
SKILLFEED_REQUIRE_LOGIN=1
SKILLFEED_SESSION_SECRET=$secret
SKILLFEED_GITHUB_LOGIN_VISIBLE=1
SKILLFEED_GITHUB_CLIENT_ID=
SKILLFEED_GITHUB_CLIENT_SECRET=
SKILLFEED_TRUSTED_PROXY_HOPS=1
SKILLFEED_TRUSTED_PROXY_IPS=127.0.0.1
SKILLFEED_SITE_DIR=/var/www/html
SKILLFEED_CORS_ORIGINS=https://skillfeeder.cn,https://www.skillfeeder.cn,https://469910093-ui.github.io
SKILLFEED_OPERATOR_LOGINS=${SKILLFEED_OPERATOR_LOGINS:-}
SKILLFEED_DEV=0
SKILLFEED_DEV_AUTH=0
EOF
  chmod 600 "$ROOT/.env"
  echo "[bootstrap] wrote $ROOT/.env (GitHub Client 还是空的)"
else
  echo "[bootstrap] keep existing $ROOT/.env"
fi

sudo cp "$ROOT/scripts/skillfeed-api.service" /etc/systemd/system/skillfeed-api.service
sudo cp "$ROOT/scripts/nginx-skillfeeder.conf" /etc/nginx/snippets/skillfeeder-api.conf

python3 - <<'PY'
from pathlib import Path
p = Path("/etc/nginx/sites-available/default")
text = p.read_text(encoding="utf-8")
needle = "include snippets/skillfeeder-api.conf;"
if needle not in text:
    old = "    server_name www.skillfeeder.cn skillfeeder.cn; # managed by Certbot\n\n\n\tlocation / {"
    new = (
        "    server_name www.skillfeeder.cn skillfeeder.cn; # managed by Certbot\n\n"
        "    include snippets/skillfeeder-api.conf;\n\n"
        "\tlocation / {"
    )
    if old not in text:
        raise SystemExit("nginx default 找不到插入点，请手工 include snippets/skillfeeder-api.conf")
    Path("/tmp/nginx-default.next").write_text(text.replace(old, new, 1), encoding="utf-8")
    print("[bootstrap] patched nginx default (staged)")
else:
    print("[bootstrap] nginx already includes api snippet")
PY

if [ -f /tmp/nginx-default.next ]; then
  sudo cp /tmp/nginx-default.next /etc/nginx/sites-available/default
  rm -f /tmp/nginx-default.next
fi

sudo nginx -t
sudo systemctl daemon-reload
sudo systemctl enable skillfeed-api
sudo systemctl restart skillfeed-api
sudo systemctl reload nginx
sleep 1
curl -fsS http://127.0.0.1:8787/health
echo
echo "[bootstrap] ok  →  https://skillfeeder.cn/health"
echo "[bootstrap] 下一步：把 GitHub OAuth Client ID/Secret 写进 $ROOT/.env 后执行："
echo "  sudo systemctl restart skillfeed-api"

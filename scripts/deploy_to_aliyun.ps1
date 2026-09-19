# 把 site/index.html 覆盖到 skillfeeder.cn 的 Nginx。
# 先做完 docs/deploy-aliyun.md 里的一次授权。
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$html = Join-Path $root "site\index.html"
$feed = Join-Path $root "site\feed.json"
$key = Join-Path $env:USERPROFILE ".ssh\skillfeed-aliyun"
$hostName = "8.133.208.149"
$user = "admin"

if (-not (Test-Path $html)) { throw "missing $html — run: python skillfeed.py publish-site --out site --full" }
if (-not (Test-Path $key)) { throw "missing $key" }

$sz = (Get-Item $html).Length
if ($sz -lt 100000) { throw "index.html too small: $sz" }

scp -i $key -o ConnectTimeout=15 $html "${user}@${hostName}:/var/www/html/index.html"
if (Test-Path $feed) {
    scp -i $key -o ConnectTimeout=15 $feed "${user}@${hostName}:/tmp/skillfeed-feed.json"
    ssh -i $key -o ConnectTimeout=15 "${user}@${hostName}" "sudo mv /tmp/skillfeed-feed.json /var/www/html/feed.json && sudo chown admin:admin /var/www/html/feed.json && sudo chmod 644 /var/www/html/feed.json"
}
ssh -i $key -o ConnectTimeout=15 "${user}@${hostName}" "grep -o '<title>.*</title>' /var/www/html/index.html && ls -lh /var/www/html/index.html /var/www/html/feed.json"
Write-Host "ok https://skillfeeder.cn/"

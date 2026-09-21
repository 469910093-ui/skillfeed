# 把 site/ 的首页和 Agent Surface 覆盖到 skillfeeder.cn 的 Nginx。
# 先做完 docs/deploy-aliyun.md 里的一次授权。
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$site = Join-Path $root "site"
$html = Join-Path $site "index.html"
$feed = Join-Path $site "feed.json"
$key = Join-Path $env:USERPROFILE ".ssh\skillfeed-aliyun"
$hostName = "8.133.208.149"
$user = "admin"
$geoFiles = @(
    "llms.txt", "llms-full.txt", "robots.txt", "sitemap.xml",
    "about.md", "faq.md", "compare.md", "catalog.json", "og.png",
    "favicon.ico", "favicon.png", "apple-touch-icon.png"
)

if (-not (Test-Path $html)) { throw "missing $html — run: python skillfeed.py publish-site --out site --full" }
if (-not (Test-Path $key)) { throw "missing $key" }

$sz = (Get-Item $html).Length
if ($sz -lt 100000) { throw "index.html too small: $sz" }

scp -i $key -o ConnectTimeout=15 $html "${user}@${hostName}:/var/www/html/index.html"
if (Test-Path $feed) {
    scp -i $key -o ConnectTimeout=15 $feed "${user}@${hostName}:/tmp/skillfeed-feed.json"
    ssh -i $key -o ConnectTimeout=15 "${user}@${hostName}" "sudo mv /tmp/skillfeed-feed.json /var/www/html/feed.json && sudo chown admin:admin /var/www/html/feed.json && sudo chmod 644 /var/www/html/feed.json"
}
foreach ($name in $geoFiles) {
    $src = Join-Path $site $name
    if (-not (Test-Path $src)) { throw "missing $src — publish-site should write Agent Surface files" }
    scp -i $key -o ConnectTimeout=15 $src "${user}@${hostName}:/tmp/skillfeed-$name"
    ssh -i $key -o ConnectTimeout=15 "${user}@${hostName}" "sudo mv /tmp/skillfeed-$name /var/www/html/$name && sudo chown admin:admin /var/www/html/$name && sudo chmod 644 /var/www/html/$name"
}
ssh -i $key -o ConnectTimeout=15 "${user}@${hostName}" "grep -o '<title>.*</title>' /var/www/html/index.html && ls -lh /var/www/html/index.html /var/www/html/llms.txt /var/www/html/catalog.json"
Write-Host "ok https://skillfeeder.cn/  https://skillfeeder.cn/llms.txt"

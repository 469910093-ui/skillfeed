# Write GitHub OAuth Client ID/Secret into Aliyun /opt/skill-feed/.env
# Run this in Windows PowerShell. Do not paste the secret into chat.
$ErrorActionPreference = "Stop"
$key = Join-Path $env:USERPROFILE ".ssh\skillfeed-aliyun"
$hostName = "8.133.208.149"
$user = "admin"
if (-not (Test-Path $key)) { throw "missing $key" }

Write-Host "Open https://github.com/settings/developers  -> OAuth Apps -> SkillFeeder"
Write-Host "Callback must be: https://skillfeeder.cn/auth/github/callback"
Write-Host ""

$clientId = (Read-Host "GitHub Client ID").Trim()
$secure = Read-Host "GitHub Client Secret" -AsSecureString
$bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
try {
    $clientSecret = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
} finally {
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
}
$clientSecret = $clientSecret.Trim()

if ($clientId -match '^(?i)(469910093-ui|your-github-login)$' -or $clientId -notmatch '^(Ov23|[0-9A-Fa-f]{20})') {
    throw "Client ID is not your GitHub username. Copy it from OAuth App page (starts with Ov23 or is 20 hex chars)."
}
if ($clientSecret.Length -lt 20) { throw "Client Secret looks too short. Click Generate a new client secret on the OAuth App page, then paste that long string." }
if ($clientId -match '[\r\n=]' -or $clientSecret -match '[\r\n=]') { throw "credentials must be a single line" }

$pyLocal = Join-Path $env:TEMP "skillfeed_set_oauth.py"
@'
from pathlib import Path
import sys
raw = sys.stdin.read().split("\n", 1)
cid, secret = raw[0].strip(), raw[1].strip()
path = Path("/opt/skill-feed/.env")
lines = path.read_text(encoding="utf-8").splitlines()
out, seen_id, seen_secret = [], False, False
for line in lines:
    if line.startswith("SKILLFEED_GITHUB_CLIENT_ID="):
        out.append("SKILLFEED_GITHUB_CLIENT_ID=" + cid)
        seen_id = True
    elif line.startswith("SKILLFEED_GITHUB_CLIENT_SECRET="):
        out.append("SKILLFEED_GITHUB_CLIENT_SECRET=" + secret)
        seen_secret = True
    else:
        out.append(line)
if not seen_id:
    out.append("SKILLFEED_GITHUB_CLIENT_ID=" + cid)
if not seen_secret:
    out.append("SKILLFEED_GITHUB_CLIENT_SECRET=" + secret)
path.write_text("\n".join(out) + "\n", encoding="utf-8")
print("oauth_keys_written")
'@ | ForEach-Object { [System.IO.File]::WriteAllText($pyLocal, $_) }

scp -i $key -o ConnectTimeout=15 $pyLocal "${user}@${hostName}:/tmp/skillfeed_set_oauth.py"
if ($LASTEXITCODE -ne 0) { throw "failed to upload helper" }

$payload = $clientId + "`n" + $clientSecret
$payload | ssh -i $key -o ConnectTimeout=15 "${user}@${hostName}" "python3 /tmp/skillfeed_set_oauth.py && rm -f /tmp/skillfeed_set_oauth.py"
if ($LASTEXITCODE -ne 0) { throw "failed to write remote .env" }

ssh -i $key -o ConnectTimeout=15 "${user}@${hostName}" "sudo systemctl restart skillfeed-api && sleep 2 && curl -fsS http://127.0.0.1:8787/health"
Write-Host ""
Write-Host "If oauth is true, open https://skillfeeder.cn/login and use GitHub."

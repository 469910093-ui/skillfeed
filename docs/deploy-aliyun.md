# 把全量站推到 skillfeeder.cn（Nginx）

公开页仍由 GitHub Pages 出包。阿里云轻量托管 `https://skillfeeder.cn/` 的 `index.html` 以及 Agent Surface（`llms.txt` / `about.md` / `catalog.json` 等）。
配好密钥后：**push `main` 或重跑 Refresh & Pages，就会自动覆盖 Nginx**，不必再开 Workbench。

登录 / 发布 / 换设备同步要另挂 FastAPI，见 `docs/deploy-api.md`。没挂时「我的」会显示游客，并引导去主站登录页。

额度限制那套不要走这条链路。`publish-site` 在 CI 里出的是全量 `index.html`。

## 一次授权（Workbench）

把下面整段贴进已经登录的黑窗口：

```bash
mkdir -p ~/.ssh
chmod 700 ~/.ssh
grep -q skillfeed-pages-deploy ~/.ssh/authorized_keys 2>/dev/null || \
  echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBK1pmPTZMHzLzbiPnmaNz/YpBZ5CmHzRNG8eH0LOYD9 skillfeed-pages-deploy' >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
sudo chown admin:admin /var/www/html/index.html
sudo chmod 644 /var/www/html/index.html
# 校验文件仍归 root，发布脚本不会动它
ls -l ~/.ssh/authorized_keys /var/www/html
```

轻量防火墙放行 **22**（你之前 `scp` 能弹出密码，说明已经开了）。

## 之后怎么发

1. 改 `feed_dashboard.py` 等页面源码并 push `main`
2. Actions 里 `Refresh & Pages` 过门禁 → 发 Pages → **Nginx · skillfeeder.cn** 把 `index.html` 和 GEO 文件 scp 上去
3. 打开 https://skillfeeder.cn/ 与 https://skillfeeder.cn/llms.txt 强制刷新

本机临时发一版（密钥在 `~/.ssh/skillfeed-aliyun`）：

```powershell
cd D:\Users\yaowenliang\Projects\skill-feed
python skillfeed.py publish-site --out site --full
.\scripts\deploy_to_aliyun.ps1
```

## Secrets（已写进仓库，不要提交私钥）

| 名字 | 值 |
|------|-----|
| `ALIYUN_HOST` | `8.133.208.149` |
| `ALIYUN_USER` | `admin` |
| `ALIYUN_SSH_KEY` | 本机 `~/.ssh/skillfeed-aliyun` 私钥 |

私钥只在本机和 GitHub Secrets，不进 git。

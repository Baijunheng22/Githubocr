# VoiceLedger OCR Worker 0.6

这是「声账 VoiceLedger」0.6 的 Cloudflare Worker 仓库。

## 这份仓库是干什么的

Cloudflare 从 GitHub 自动读取这里的代码，并部署到现有的 `voiceledger-ocr` Worker。

## 重要

不要把火山引擎 AK/SK 写进任何文件，也不要提交到 GitHub。
它们应该继续保存在 Cloudflare Worker 的 **Settings → Variables and Secrets** 里：

- `VOLC_ACCESS_KEY_ID`
- `VOLC_SECRET_ACCESS_KEY`

## Cloudflare 连接后推荐设置

- Production branch: `main`
- Build command: 留空
- Deploy command: `npx wrangler deploy`
- Root directory: `/` 或留空

部署完成后访问：

`https://voiceledger-ocr.f2gwzrt4st.workers.dev/health`

正常应返回包含：

- `"ok": true`
- `"provider": "火山引擎通用文字识别"`
- `"model": "OCRNormal"`
- `"configured": true`
wahhty

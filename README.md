# VoiceLedger OCR Worker · 0.9 Beta

用于现有 `voiceledger-ocr` Cloudflare Worker 的 0.9 更新。

新增：`mode: "guagua"` 呱呱录音宝月账表格解析；原 AU OCR 继续兼容。

如果你已经通过 GitHub 连接 Cloudflare：最简单的方法是覆盖仓库根目录 `worker.js` 并提交，等待原构建自动 `npx wrangler deploy`。

现有 Cloudflare Runtime Secrets 不变：
- `VOLC_ACCESS_KEY_ID`
- `VOLC_SECRET_ACCESS_KEY`

部署后访问 `/health`，应看到 `version: "0.9"` 和 `features: ["au", "guagua"]`。

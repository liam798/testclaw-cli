# testclaw

`testclaw` 是 TestClaw 面向 AI Agent、工程师与 CI 的一方 Node CLI。

目标是把 AI 模块主架构收敛为：

- `API`
  - `sonic-server` 继续作为能力真源
- `CLI`
  - `testclaw` 负责确定性执行、参数标准化、本地 `adb` 与远端 API 混合编排
- `SKILL`
  - `testclaw-skills` 负责自然语言触发与工作流编排

`testclaw-mcp` 继续保留，但定位改为兼容层，用于：

- MCP 客户端接入
- 远程 HTTP MCP 暴露
- 无法直接运行 `testclaw` 的场景

当前目录结构：

```text
testclaw-cli/
├── package.json
├── bin/
│   └── testclaw.js
├── lib/
│   ├── cli.js
│   ├── sonic-backend.js
│   ├── adb-backend.js
│   ├── oauth-client.js
│   └── session.js
└── tests/
```

## 安装

外部用户推荐直接从 GitHub 安装：

```bash
npm install -g git+https://github.com/liam798/testclaw-cli.git
```

也可以使用 npm 的 GitHub shorthand：

```bash
npm install -g github:liam798/testclaw-cli
```

安装后验证：

```bash
testclaw --help
testclaw --json doctor
```

配置 TestClaw Server 并登录：

```bash
testclaw config set base_url https://testclaw.vvicat.dev
testclaw login
testclaw --json whoami
```

开发者本地仓库安装：

```bash
git clone git@github.com:liam798/testclaw-cli.git
cd testclaw-cli
npm install -g .
```

## 入口

正式入口：

```bash
testclaw --help
```

诊断当前安装、配置、认证和服务连通性：

```bash
testclaw --json doctor
```

推荐先把服务地址写进默认配置文件：

```bash
testclaw config set base_url https://testclaw.vvicat.dev
```

默认配置文件路径：

```text
~/.config/testclaw/config.json
```

认证信息单独保存在：

```text
~/.config/testclaw/auth.json
```

`config` 使用 key/value 保存，支持以下配置项：

```bash
testclaw config set base_url https://testclaw.vvicat.dev
testclaw config set adb_bin /opt/homebrew/bin/adb
testclaw config get base_url
testclaw config list
testclaw config unset adb_bin
```

配置文件会按 key/value 形式落盘：

```json
{
  "base_url": "https://testclaw.vvicat.dev",
  "adb_bin": "adb"
}
```

查看当前配置：

```bash
testclaw config list
```

浏览器 OAuth 登录：

```bash
testclaw login
```

退出登录会清理 `auth.json` 中的认证信息，不会改动 `config.json`：

```bash
testclaw logout
```

默认会自动推导 OAuth 地址为：

```text
https://testclaw.vvicat.dev/api/oauth
```

## 常用示例

```bash
testclaw config set base_url https://testclaw.vvicat.dev
testclaw --json doctor
testclaw login
testclaw --json whoami
testclaw --json module create --project-id 9 --name 登录模块
testclaw --json case create --project-id 9 --platform 1 --name 登录成功用例 --module-id 101 --version v1.0.0 --des 验证登录成功流程
testclaw --json step create --project-id 9 --platform 1 --case-id 201 --step-type click --element-id 301
testclaw --json suite create --project-id 9 --platform 1 --name 登录回归套件 --cover 1 --is-open-perfmon 0 --perfmon-interval 1000 --device-id 201 --test-case-id 201
testclaw --json package upload --file ./demo.apk --project-id 9 --pkg-name demo.apk --platform android --branch main
testclaw --json device list --status ONLINE
testclaw --json device prepare-android-debug --device-id 1
testclaw --json app open --adb-address 127.0.0.1:56001 --app-id com.demo.app
testclaw --json suite run --id 12
```

## Android 安全分析 MVP

`testclaw security` 提供 Android 动静态混合分析流水线的第一版可运行入口，和仓库文档 `docs/android-hybrid-adware-analysis-pipeline.html` 对齐。

当前 CLI MVP 已完成：

- 样本 SHA256 登记与产物目录创建
- 本地静态风险评分
- URL、域名、IP、包名、Base64、Hex、高熵字符串候选提取
- LLM 复核输入包生成
- 统一 JSON 报告生成
- 流水线阶段状态、证据时间线、字符串解密候选、规则草案、产物清单生成
- 可读 HTML 报告生成
- 报告完整性与“LLM 不单点定罪”校验
- MobSF、YARA、Quark、动态设备池、Frida/DEX dump 的插件状态占位

运行本地分析：

```bash
testclaw --json security analyze --file ./suspicious.apk --out-dir ./security-artifacts
```

在完整安全实验室环境中，可同时接入外部引擎和 Android 设备：

```bash
testclaw --json security analyze \
  --file ./suspicious.apk \
  --out-dir ./security-artifacts \
  --yara-bin yara \
  --yara-rules /opt/yara-rules/android \
  --quark-bin quark \
  --quark-rules /opt/quark-rules \
  --mobsf-url http://127.0.0.1:8000 \
  --mobsf-key "$MOBSF_API_KEY" \
  --adb-address 127.0.0.1:56001 \
  --package-name com.example.suspicious \
  --llm-command /opt/testclaw/security-llm-review
```

参数说明：

- `--yara-bin` / `--yara-rules`：执行 YARA 扫描并写入 `yara/hits.json`。
- `--quark-bin` / `--quark-rules`：执行 Quark-Engine 行为链扫描并写入 `quark/report.json`。
- `--mobsf-url` / `--mobsf-key`：调用 MobSF REST API 上传与扫描 APK，并写入 `mobsf/report.json`。
- `--adb-address` / `--package-name`：在指定 Android 设备上安装、启动样本并采集 logcat、dumpsys、截图触发记录。
- `--uninstall-after-dynamic`：动态执行后尝试卸载样本。
- `--llm-command`：从 stdin 接收 LLM 复核输入 JSON，stdout 输出复核结果；结果写入 `llm/review-output.json`。
- `--llm-timeout-seconds`：控制 LLM 命令超时时间。

读取报告：

```bash
testclaw --json security report --report ./security-artifacts/<sha256>/report.json
```

导出 IOC：

```bash
testclaw --json security ioc --report ./security-artifacts/<sha256>/report.json
```

查看全部工程产物：

```bash
testclaw --json security artifacts --report ./security-artifacts/<sha256>/report.json
```

校验报告是否具备必需产物、阶段结构和证据约束：

```bash
testclaw --json security validate --report ./security-artifacts/<sha256>/report.json
```

创建并回传平台化安全分析任务：

```bash
testclaw --json security task create \
  --project-id 9 \
  --sample-sha256 <sha256> \
  --package-name com.example.suspicious \
  --profile adware-deep

testclaw --json security task ingest-report --task-id 601 --report ./security-artifacts/<sha256>/report.json
testclaw --json security task report --task-id 601
testclaw --json security task list --project-id 9
```

每次分析会在样本 SHA256 目录下生成：

- `report.json`：统一结构化报告。
- `report.html`：可读 HTML 报告。
- `artifact-manifest.json`：产物索引、大小和 SHA256。
- `evidence-timeline.json`：样本登记、发现项和插件产物的证据时间线。
- `strings/decryption-candidates.json`：Base64、Hex、高熵字符串候选和可复现解密计划。
- `rules/suggestions.json`：YARA、Quark 和 IOC 规则草案。
- `llm/review-input.json`：最小化、结构化的 LLM 复核输入。

工程化接入点：

- `sonic-server` 提供 `/controller/security/tasks` 和 `/controller/security/tasks/{taskId}/report`，保存任务、风险等级和结构化报告。
- `sonic-agent` 提供 Android 安全分析执行计划器，覆盖设备清理、代理抓包、安装启动、Frida/DEX、UI 探索、证据采集和设备恢复阶段。
- `sonic-client-web` 提供项目内“安全分析”页面，展示任务列表、风险摘要、证据时间线、IOC 和规则草案。

说明：外部引擎仍以可替换插件形式接入。MobSF、YARA、Quark、Frida、设备池、MITM/PCAP 和企业 LLM Gateway 的实际运行状态会以明确的 `pluginStatuses` 写入报告；LLM 结果只做辅助解释，不能单点定罪。

## JSON 输出策略

`--json` 模式下：

- 成功结果只向 stdout 输出 JSON。
- 错误结果向 stderr 输出稳定 JSON，形如：

```json
{
  "ok": false,
  "error": {
    "type": "SonicCliError",
    "message": "未知配置项: token"
  }
}
```

- CLI 不会输出完整 token。`doctor` 只返回 `has_token`、`has_oauth_access_token`、`token_source` 等布尔或来源信息。
- 原始 API 逃生口为：

```bash
testclaw --json raw request --method GET --path /projects/list
```

## 测试

```bash
git clone git@github.com:liam798/testclaw-cli.git
cd testclaw-cli
npm install
npm test
```

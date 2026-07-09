# testclaw 测试说明

## 安装

```bash
cd /Volumes/Disk_APFS/Work/XiaMao/Project/TestClaw/testclaw-cli
npm install -g .
```

## 执行测试

```bash
npm test
```

## 验收标准

- `testclaw --help` 可执行
- `testclaw` 无参数时输出帮助，不进入交互模式
- `--json` 输出稳定
- 关键工作流可通过假 Sonic 服务端和假 `adb` 通过

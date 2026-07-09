const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const RISK_LEVELS = [
  { min: 90, level: "malicious_high_confidence", label: "恶意高置信度" },
  { min: 60, level: "high", label: "高风险" },
  { min: 30, level: "suspicious", label: "可疑" },
  { min: 0, level: "low", label: "低风险" },
];
const ENGINE_NAMES = ["mobsf", "yara", "quark", "dynamicExecution", "fridaDex", "mitmPcap", "llm"];

function sha256(buffer) {
  return crypto.createHash("sha256").update(buffer).digest("hex");
}

function unique(values) {
  return Array.from(new Set(values.filter(Boolean))).sort();
}

function readSample(filePath) {
  const absolutePath = path.resolve(filePath);
  const buffer = fs.readFileSync(absolutePath);
  return {
    absolutePath,
    buffer,
    text: buffer.toString("latin1"),
    hash: sha256(buffer),
    stat: fs.statSync(absolutePath),
  };
}

function hasAny(text, patterns) {
  return patterns.some((pattern) => text.includes(pattern));
}

function addFinding(findings, finding) {
  findings.push({
    evidenceRefs: [],
    ...finding,
  });
}

function writeJson(filePath, payload) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, `${JSON.stringify(payload, null, 2)}\n`, "utf8");
}

function writeText(filePath, payload) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, payload, "utf8");
}

function runCommand(command, args, options = {}) {
  const startedAt = new Date().toISOString();
  const result = spawnSync(command, args, {
    encoding: "utf8",
    input: options.input,
    timeout: options.timeoutMs || 120000,
  });
  return {
    command: [command, ...args].join(" "),
    startedAt,
    finishedAt: new Date().toISOString(),
    exitCode: result.status,
    signal: result.signal,
    stdout: result.stdout || "",
    stderr: result.stderr || "",
    error: result.error ? result.error.message : null,
  };
}

function engineRemediationHint(engine, status) {
  if (status === "completed") {
    return "保留产物并在最终报告中交叉引用该引擎证据。";
  }
  if (status === "failed") {
    return "检查引擎命令、凭证、规则目录、设备连接和 stderr，修复后重新执行 security analyze。";
  }
  if (engine === "dynamicExecution") {
    return "配置可用 Android 设备、ADB 地址和包名后重新执行动态分析。";
  }
  if (engine === "fridaDex") {
    return "配置 Frida/frida-dexdump 命令或已采集 DEX 产物后重新执行 security analyze。";
  }
  if (engine === "mitmPcap") {
    return "配置 MITM/PCAP 采集命令或已采集 pcap 产物后重新执行 security analyze。";
  }
  if (engine === "llm") {
    return "配置企业 LLM Gateway 或 llm-command 后执行辅助复核。";
  }
  return "配置真实外部引擎、规则或服务地址后重新执行 security analyze。";
}

function defaultEngineTimeoutMs(engine) {
  return {
    mobsf: 300000,
    yara: 120000,
    quark: 300000,
    dynamicExecution: 120000,
    fridaDex: 180000,
    mitmPcap: 180000,
    llm: 120000,
  }[engine] || 120000;
}

function engineEnabled(engine, status) {
  if (status.artifactPath) {
    return true;
  }
  return ["completed", "failed"].includes(status.status);
}

function normalizeEngineStatus(engine, status, options = {}) {
  const timeoutMs = {
    mobsf: options.mobsfTimeoutSeconds ? options.mobsfTimeoutSeconds * 1000 : defaultEngineTimeoutMs(engine),
    yara: options.yaraTimeoutSeconds ? options.yaraTimeoutSeconds * 1000 : defaultEngineTimeoutMs(engine),
    quark: options.quarkTimeoutSeconds ? options.quarkTimeoutSeconds * 1000 : defaultEngineTimeoutMs(engine),
    dynamicExecution: options.dynamicTimeoutSeconds ? options.dynamicTimeoutSeconds * 1000 : defaultEngineTimeoutMs(engine),
    fridaDex: options.fridaDexTimeoutSeconds ? options.fridaDexTimeoutSeconds * 1000 : defaultEngineTimeoutMs(engine),
    mitmPcap: options.mitmPcapTimeoutSeconds ? options.mitmPcapTimeoutSeconds * 1000 : defaultEngineTimeoutMs(engine),
    llm: options.llmTimeoutSeconds ? options.llmTimeoutSeconds * 1000 : defaultEngineTimeoutMs(engine),
  }[engine];
  return {
    engine,
    enabled: engineEnabled(engine, status),
    timeoutMs,
    remediationHint: status.remediationHint || engineRemediationHint(engine, status.status),
    ...status,
  };
}

function normalizePluginStatuses(report, options = {}) {
  const next = {};
  for (const engine of ENGINE_NAMES) {
    next[engine] = normalizeEngineStatus(engine, report.pluginStatuses[engine] || {}, options);
  }
  report.pluginStatuses = next;
}

function extractIocs(text) {
  const urls = unique(text.match(/\bhttps?:\/\/[^\s"'<>\\)]+/gi) || []);
  const domains = unique([
    ...(text.match(/\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|cn|dev|xyz|top|info|biz|cc|ru|app|example)\b/gi) || []),
    ...urls.map((item) => {
      try {
        return new URL(item).hostname;
      } catch {
        return "";
      }
    }),
  ]);
  const ips = unique(text.match(/\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g) || []);
  const packageNames = unique(text.match(/\b(?:com|android|org|net)\.[a-zA-Z0-9_.$-]{5,}\b/g) || []);
  const base64Candidates = unique(
    (text.match(/(?:^|[^A-Za-z0-9+/])[A-Za-z0-9+/]{24,}={0,2}(?=$|[^A-Za-z0-9+/=])/g) || [])
      .map((item) => item.replace(/^[^A-Za-z0-9+/]+/, ""))
      .filter((item) => item.length % 4 === 0),
  );
  const hexCandidates = unique(text.match(/\b[0-9a-fA-F]{32,}\b/g) || []);
  const highEntropyStrings = unique(
    (text.match(/[A-Za-z0-9_+\-/=.$]{24,}/g) || []).filter((item) => {
      const chars = new Set(item);
      return chars.size >= 12 && !urls.includes(item);
    }),
  ).slice(0, 100);
  return {
    urls,
    domains,
    ips,
    packageNames,
    encryptedStringCandidates: {
      base64: base64Candidates.slice(0, 100),
      hex: hexCandidates.slice(0, 100),
      highEntropy: highEntropyStrings,
    },
  };
}

function scoreStaticEvidence(text, iocs) {
  const findings = [];
  let score = 0;

  if (hasAny(text, ["SYSTEM_ALERT_WINDOW", "android.permission.SYSTEM_ALERT_WINDOW"])) {
    score += 25;
    addFinding(findings, {
      id: "dangerous_permission_overlay",
      severity: "high",
      score: 25,
      title: "申请悬浮窗权限",
      description: "样本包含 SYSTEM_ALERT_WINDOW，符合隐藏弹窗广告软件的关键静态特征。",
    });
  }

  if (hasAny(text, ["RECEIVE_BOOT_COMPLETED", "REQUEST_IGNORE_BATTERY_OPTIMIZATIONS"])) {
    score += 15;
    addFinding(findings, {
      id: "persistence_permission_combo",
      severity: "medium",
      score: 15,
      title: "存在持久化相关权限",
      description: "样本包含开机自启或忽略电池优化相关权限，可能用于后台常驻。",
    });
  }

  if (hasAny(text, ["DexClassLoader", "PathClassLoader", "InMemoryDexClassLoader", "loadDex"])) {
    score += 20;
    addFinding(findings, {
      id: "dynamic_dex_loading",
      severity: "high",
      score: 20,
      title: "存在动态 DEX 加载迹象",
      description: "样本包含动态加载相关 API，需要结合运行期 DEX dump 进一步确认。",
    });
  }

  if (hasAny(text, ["setComponentEnabledSetting", "COMPONENT_ENABLED_STATE_DISABLED"])) {
    score += 15;
    addFinding(findings, {
      id: "launcher_hide_candidate",
      severity: "medium",
      score: 15,
      title: "存在隐藏 Launcher 图标候选行为",
      description: "样本包含组件启停 API，可能用于隐藏入口图标。",
    });
  }

  if (hasAny(text, ["WindowManager.addView", "TYPE_APPLICATION_OVERLAY", "TYPE_SYSTEM_ALERT"])) {
    score += 25;
    addFinding(findings, {
      id: "background_overlay_candidate",
      severity: "high",
      score: 25,
      title: "存在后台悬浮窗弹窗候选行为",
      description: "样本包含 WindowManager.addView 或系统弹窗类型，符合恶意广告弹窗关键行为。",
    });
  }

  if (hasAny(text, ["TaskDescription", "setTaskDescription"])) {
    score += 10;
    addFinding(findings, {
      id: "task_masquerading_candidate",
      severity: "medium",
      score: 10,
      title: "存在最近任务伪装候选行为",
      description: "样本包含 TaskDescription 相关调用，可能用于伪装任务标题或图标。",
    });
  }

  if (hasAny(text, ["generic", "goldfish", "ranchu", "qemu", "Genymotion", "frida", "27042"])) {
    score += 15;
    addFinding(findings, {
      id: "anti_analysis_candidate",
      severity: "medium",
      score: 15,
      title: "存在反模拟器或反 Hook 线索",
      description: "样本包含常见模拟器或 Frida 检测关键字。",
    });
  }

  if (iocs.urls.length || iocs.domains.length) {
    score += 15;
    addFinding(findings, {
      id: "network_ioc_candidate",
      severity: "medium",
      score: 15,
      title: "存在网络 IOC 候选",
      description: "样本中提取到 URL 或域名，需结合动态流量验证。",
    });
  }

  if (
    iocs.encryptedStringCandidates.base64.length ||
    iocs.encryptedStringCandidates.hex.length ||
    iocs.encryptedStringCandidates.highEntropy.length
  ) {
    score += 10;
    addFinding(findings, {
      id: "encrypted_string_candidate",
      severity: "medium",
      score: 10,
      title: "存在加密或编码字符串候选",
      description: "样本包含 Base64、Hex 或高熵字符串，适合进入 LLM 辅助字符串解密流程。",
    });
  }

  const risk = RISK_LEVELS.find((item) => score >= item.min);
  return {
    score,
    level: risk.level,
    label: risk.label,
    findings,
  };
}

function buildPluginStatuses() {
  return {
    mobsf: {
      status: "pending_external_engine",
      role: "APK 静态门禁和二次扫描",
      nextStep: "接入 MobSF REST API 后写入 mobsf/report.json。",
    },
    yara: {
      status: "pending_external_engine",
      role: "已知家族、DEX、配置和 IOC 规则匹配",
      nextStep: "接入本地 yara 二进制和规则目录后写入 yara/hits.json。",
    },
    quark: {
      status: "pending_external_engine",
      role: "Android API 行为链分析",
      nextStep: "接入 quark-engine 和规则目录后写入 quark/report.json。",
    },
    dynamicExecution: {
      status: "pending_device_pool",
      role: "TestClaw 设备池动态执行、截图、logcat、流量和 DEX dump",
      nextStep: "接入 sonic-agent runner 和设备调度后写入 dynamic/。",
    },
    fridaDex: {
      status: "pending_external_engine",
      role: "Frida Hook 与运行期 DEX dump",
      nextStep: "接入 Frida/frida-dexdump 命令或导入已采集 DEX 产物后写入 dex/。",
    },
    mitmPcap: {
      status: "pending_external_engine",
      role: "MITM/PCAP 真实流量采集",
      nextStep: "接入 MITM 代理、pcap 采集命令或导入已采集流量后写入 network/。",
    },
    llm: {
      status: "prepared_review_package",
      role: "证据归纳、字符串解密辅助、规则建议和报告解释",
      nextStep: "将 llm/review-input.json 交给企业 LLM Gateway。",
    },
  };
}

function buildPipelineStages() {
  return [
    { id: "sample_registration", name: "样本登记与去重", status: "pending", required: true },
    { id: "static_triage", name: "静态初筛与 IOC 提取", status: "pending", required: true },
    { id: "mobsf_static_gate", name: "MobSF 静态门禁", status: "pending_external_engine", required: false },
    { id: "yara_scan", name: "YARA 指纹匹配", status: "pending_external_engine", required: false },
    { id: "quark_behavior_chain", name: "Quark 行为链分析", status: "pending_external_engine", required: false },
    { id: "dynamic_execution", name: "Android 动态执行", status: "pending_device_pool", required: false },
    { id: "dex_capture", name: "运行期 DEX 捕获", status: "pending_device_pool", required: false },
    { id: "network_capture", name: "MITM/PCAP 流量取证", status: "pending_device_pool", required: false },
    { id: "string_decryption", name: "自动字符串解密候选", status: "pending", required: true },
    { id: "llm_review", name: "LLM 证据归纳与规则建议", status: "prepared_review_package", required: false },
    { id: "reporting", name: "统一风险报告", status: "pending", required: true },
  ];
}

function setStageStatus(report, id, status, detail = {}) {
  const stage = report.pipeline.stages.find((item) => item.id === id);
  if (stage) {
    Object.assign(stage, detail, { status });
  }
}

function toSeverityScore(severity) {
  return { high: 3, medium: 2, low: 1, info: 0 }[severity] ?? 0;
}

function buildEvidenceTimeline(report) {
  const events = [
    {
      type: "sample_registered",
      stage: "sample_registration",
      title: "样本已登记",
      evidenceRefs: [report.sample.artifactPath],
      sampleSha256: report.sample.sha256,
    },
  ];
  for (const finding of [...report.findings].sort((a, b) => toSeverityScore(b.severity) - toSeverityScore(a.severity))) {
    events.push({
      type: "finding",
      stage: finding.stage || "static_triage",
      title: finding.title,
      findingId: finding.id,
      severity: finding.severity,
      score: finding.score || 0,
      evidenceRefs: finding.evidenceRefs || [],
    });
  }
  for (const [plugin, status] of Object.entries(report.pluginStatuses)) {
    if (status.artifactPath) {
      events.push({
        type: "artifact",
        stage: plugin,
        title: `${plugin} ${status.status}`,
        evidenceRefs: [status.artifactPath],
      });
    }
  }
  return events.map((event, index) => ({ order: index + 1, ...event }));
}

function buildStringDecryptionPlan(report) {
  const candidates = report.iocs.encryptedStringCandidates;
  return {
    status: candidates.base64.length || candidates.hex.length || candidates.highEntropy.length ? "candidates_extracted" : "no_candidate",
    candidates,
    evaluationPlan: [
      "优先对 Base64/Hex 候选做可逆解码并保留输入、输出和脚本版本。",
      "对高熵字符串结合反编译调用点定位解密函数，能静态求值时使用隔离脚本执行。",
      "无法静态求值时通过 Frida Hook 解密函数返回值，并把返回值与网络请求、DexClassLoader 路径或反射调用交叉验证。",
      "未被代码调用链或动态证据验证的解密结果只进入人工复核，不参与恶意判定。",
    ],
    requiredEvidence: [
      "代码位置或 smali 函数签名",
      "输入字符串与输出字符串",
      "解密脚本或 Hook 记录",
      "网络、动态加载、YARA 或 Quark 交叉验证证据",
    ],
  };
}

function buildRuleSuggestions(report) {
  const highValueFindings = report.findings.filter((finding) => (finding.score || 0) >= 15);
  return {
    yara: highValueFindings.map((finding) => ({
      id: finding.id,
      title: `${finding.title} YARA 草案`,
      confidence: finding.severity === "high" ? "medium" : "low",
      sourceFinding: finding.id,
      rationale: finding.description,
      evidenceRefs: finding.evidenceRefs || [],
    })),
    quark: highValueFindings
      .filter((finding) => /dex|overlay|launcher|task|permission|dynamic|window/i.test(finding.id))
      .map((finding) => ({
        id: finding.id,
        title: `${finding.title} Quark 行为链草案`,
        confidence: finding.severity === "high" ? "medium" : "low",
        sourceFinding: finding.id,
        rationale: "基于 HTML 方案中的敏感 API 组合和调用链模型生成，需要人工转写为正式 Quark 规则。",
        evidenceRefs: finding.evidenceRefs || [],
      })),
    ioc: {
      domains: report.iocs.domains,
      urls: report.iocs.urls,
      ips: report.iocs.ips,
    },
  };
}

function htmlEscape(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function buildHtmlReport(report) {
  const findings = report.findings
    .map((finding) => `<tr><td>${htmlEscape(finding.severity)}</td><td>${htmlEscape(finding.score || 0)}</td><td>${htmlEscape(finding.title)}</td><td>${htmlEscape(finding.description)}</td></tr>`)
    .join("\n");
  const stages = report.pipeline.stages
    .map((stage) => `<tr><td>${htmlEscape(stage.id)}</td><td>${htmlEscape(stage.name)}</td><td>${htmlEscape(stage.status)}</td></tr>`)
    .join("\n");
  const iocs = [...report.iocs.urls, ...report.iocs.domains, ...report.iocs.ips]
    .slice(0, 200)
    .map((ioc) => `<li>${htmlEscape(ioc)}</li>`)
    .join("\n");
  return `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <title>Android 安全分析报告 - ${htmlEscape(report.sample.sha256.slice(0, 12))}</title>
  <style>
    body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC",Arial,sans-serif;margin:32px;color:#1f2937;line-height:1.6}
    h1{font-size:28px;margin:0 0 8px} h2{margin-top:28px;border-bottom:1px solid #dbe3ef;padding-bottom:8px}
    table{border-collapse:collapse;width:100%;font-size:14px}td,th{border:1px solid #dbe3ef;padding:8px;text-align:left;vertical-align:top}th{background:#f1f5f9}
    .risk{display:inline-block;padding:4px 10px;border-radius:999px;background:#eef7f6;color:#115e59;font-weight:700}
  </style>
</head>
<body>
  <h1>Android 动静态混合分析报告</h1>
  <p>样本: <code>${htmlEscape(report.sample.fileName)}</code> / <code>${htmlEscape(report.sample.sha256)}</code></p>
  <p>风险: <span class="risk">${htmlEscape(report.risk.label)} ${htmlEscape(report.risk.score)}</span></p>
  <h2>阶段状态</h2>
  <table><thead><tr><th>ID</th><th>阶段</th><th>状态</th></tr></thead><tbody>${stages}</tbody></table>
  <h2>发现项</h2>
  <table><thead><tr><th>级别</th><th>分值</th><th>标题</th><th>说明</th></tr></thead><tbody>${findings}</tbody></table>
  <h2>IOC</h2>
  <ul>${iocs}</ul>
</body>
</html>
`;
}

function artifactEntry(kind, filePath, rootDir) {
  const exists = Boolean(filePath && fs.existsSync(filePath));
  const stat = exists ? fs.statSync(filePath) : null;
  return {
    kind,
    path: filePath,
    relativePath: filePath ? path.relative(rootDir, filePath) : null,
    exists,
    sizeBytes: stat ? stat.size : 0,
    sha256: stat && stat.isFile() ? sha256(fs.readFileSync(filePath)) : null,
  };
}

function buildArtifactIndex(report) {
  const rootDir = report.artifacts.rootDir;
  const configured = [
    ["sample", report.artifacts.sampleCopyPath],
    ["json_report", report.artifacts.reportPath],
    ["llm_review_input", report.artifacts.llmReviewPath],
    ["pipeline_manifest", report.artifacts.manifestPath],
    ["evidence_timeline", report.artifacts.timelinePath],
    ["string_candidates", report.artifacts.stringCandidatesPath],
    ["rule_suggestions", report.artifacts.ruleSuggestionsPath],
    ["html_report", report.artifacts.htmlReportPath],
  ];
  for (const status of Object.values(report.pluginStatuses || {})) {
    if (status.artifactPath) {
      configured.push(["plugin_artifact", status.artifactPath]);
    }
  }
  const engineStatuses = Object.entries(report.pluginStatuses || {}).map(([engine, status]) => ({
    engine: status.engine || engine,
    status: status.status,
    enabled: Boolean(status.enabled),
    artifactPath: status.artifactPath || null,
    artifactExists: Boolean(status.artifactPath && fs.existsSync(status.artifactPath)),
    timeoutMs: status.timeoutMs || defaultEngineTimeoutMs(engine),
    remediationHint: status.remediationHint || engineRemediationHint(engine, status.status),
  }));
  return {
    sample: report.sample,
    rootDir,
    files: configured.map(([kind, filePath]) => artifactEntry(kind, filePath, rootDir)),
    engineStatuses,
  };
}

function validateSecurityReportPayload(report) {
  const artifactIndex = buildArtifactIndex(report);
  const requiredKinds = new Set(["sample", "json_report", "llm_review_input", "pipeline_manifest", "evidence_timeline", "string_candidates", "rule_suggestions", "html_report"]);
  const requiredArtifacts = artifactIndex.files.filter((file) => requiredKinds.has(file.kind));
  const llmFindings = report.findings.filter((finding) => finding.id === "llm_review_completed");
  const nonLlmScore = report.findings
    .filter((finding) => finding.id !== "llm_review_completed")
    .reduce((sum, finding) => sum + (finding.score || 0), 0);
  const expectedEngines = ENGINE_NAMES;
  const manifestEngineNames = new Set((artifactIndex.engineStatuses || []).map((engine) => engine.engine));
  const pluginStatuses = report.pluginStatuses || {};
  const enabledEngines = expectedEngines
    .map((engine) => pluginStatuses[engine])
    .filter((status) => status && status.enabled);
  const checks = [
    {
      name: "required_artifacts_exist",
      ok: requiredArtifacts.every((file) => file.exists),
      detail: requiredArtifacts.map((file) => ({ kind: file.kind, exists: file.exists, path: file.path })),
    },
    {
      name: "pipeline_has_required_stages",
      ok: ["sample_registration", "static_triage", "string_decryption", "reporting"].every((id) => report.pipeline.stages.some((stage) => stage.id === id)),
    },
    {
      name: "findings_have_evidence_refs",
      ok: report.findings.every((finding) => Array.isArray(finding.evidenceRefs)),
    },
    {
      name: "plugin_statuses_cover_engines",
      ok: expectedEngines.every((engine) => {
        const status = pluginStatuses[engine];
        return status && status.engine === engine && typeof status.enabled === "boolean" && typeof status.timeoutMs === "number" && Boolean(status.remediationHint);
      }),
      detail: expectedEngines.map((engine) => ({ engine, present: Boolean(pluginStatuses[engine]) })),
    },
    {
      name: "enabled_engines_have_artifacts",
      ok: enabledEngines.every((status) => Boolean(status.artifactPath && fs.existsSync(status.artifactPath))),
      detail: enabledEngines.map((status) => ({
        engine: status.engine,
        artifactPath: status.artifactPath || null,
        artifactExists: Boolean(status.artifactPath && fs.existsSync(status.artifactPath)),
      })),
    },
    {
      name: "manifest_records_all_engines",
      ok: expectedEngines.every((engine) => manifestEngineNames.has(engine)),
      detail: artifactIndex.engineStatuses,
    },
    {
      name: "llm_not_sole_conviction",
      ok: !llmFindings.length || nonLlmScore >= 30 || report.risk.level === "low",
      detail: { llmFindingCount: llmFindings.length, nonLlmScore, riskLevel: report.risk.level },
    },
  ];
  return {
    ok: checks.every((check) => check.ok),
    sample: report.sample,
    risk: report.risk,
    checks,
    artifactIndex,
  };
}

function appendToolFinding(report, finding) {
  report.findings.push({
    evidenceRefs: [],
    ...finding,
  });
  report.risk.score += finding.score || 0;
}

function refreshRiskLevel(report) {
  const risk = RISK_LEVELS.find((item) => report.risk.score >= item.min);
  report.risk.level = risk.level;
  report.risk.label = risk.label;
}

function runYaraIfConfigured(report, options, samplePath) {
  if (!options.yaraRules) {
    return;
  }
  const yaraBin = options.yaraBin || "yara";
  const result = runCommand(yaraBin, [options.yaraRules, samplePath]);
  const artifactPath = path.join(report.artifacts.rootDir, "yara", "hits.json");
  const hits = result.stdout
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);
  const payload = { status: result.exitCode === 0 || hits.length ? "completed" : "failed", hits, result };
  writeJson(artifactPath, payload);
  report.pluginStatuses.yara = {
    status: payload.status,
    role: "已知家族、DEX、配置和 IOC 规则匹配",
    artifactPath,
    hitCount: hits.length,
  };
  if (hits.length) {
    appendToolFinding(report, {
      id: "yara_rule_hit",
      severity: "high",
      score: 40,
      title: "YARA 命中安全规则",
      description: `YARA 命中 ${hits.length} 条规则，需要结合规则内容确认家族或行为标签。`,
      evidenceRefs: [artifactPath],
    });
  }
}

function runQuarkIfConfigured(report, options, samplePath) {
  if (!options.quarkRules) {
    return;
  }
  const quarkBin = options.quarkBin || "quark";
  const result = runCommand(quarkBin, ["-a", samplePath, "-r", options.quarkRules], {
    timeoutMs: options.quarkTimeoutSeconds ? options.quarkTimeoutSeconds * 1000 : 300000,
  });
  const artifactPath = path.join(report.artifacts.rootDir, "quark", "report.json");
  const output = `${result.stdout}\n${result.stderr}`;
  const matched = result.exitCode === 0 && /Confidence Score:\s*(?:[6-9]\d|100)%|置信度\s*(?:[6-9]\d|100)%|行为链|hidden overlay/i.test(output);
  const payload = { status: result.exitCode === 0 ? "completed" : "failed", matched, result };
  writeJson(artifactPath, payload);
  report.pluginStatuses.quark = {
    status: payload.status,
    role: "Android API 行为链分析",
    artifactPath,
    matched,
  };
  if (matched) {
    appendToolFinding(report, {
      id: "quark_behavior_chain_hit",
      severity: "high",
      score: 30,
      title: "Quark 命中行为链线索",
      description: "Quark 输出包含行为链或置信度线索，需要结合规则和反编译结果复核。",
      evidenceRefs: [artifactPath],
    });
  }
}

async function runMobsfIfConfigured(report, options, samplePath) {
  if (!options.mobsfUrl) {
    return;
  }
  const baseUrl = options.mobsfUrl.replace(/\/+$/, "");
  const apiKey = options.mobsfKey || process.env.MOBSF_API_KEY || "";
  const artifactPath = path.join(report.artifacts.rootDir, "mobsf", "report.json");
  const headers = apiKey ? { Authorization: apiKey } : {};
  try {
    const form = new FormData();
    form.append("file", new Blob([fs.readFileSync(samplePath)]), path.basename(samplePath));
    const uploadResponse = await fetch(`${baseUrl}/api/v1/upload`, { method: "POST", headers, body: form });
    const upload = await uploadResponse.json();
    if (!uploadResponse.ok) {
      throw new Error(`MobSF upload failed: HTTP ${uploadResponse.status}`);
    }
    const scanBody = new URLSearchParams({ hash: upload.hash || report.sample.sha256 });
    const scanResponse = await fetch(`${baseUrl}/api/v1/scan`, {
      method: "POST",
      headers: { ...headers, "Content-Type": "application/x-www-form-urlencoded" },
      body: scanBody,
    });
    const scan = await scanResponse.json();
    if (!scanResponse.ok) {
      throw new Error(`MobSF scan failed: HTTP ${scanResponse.status}`);
    }
    writeJson(artifactPath, { status: "completed", upload, scan });
    report.pluginStatuses.mobsf = {
      status: "completed",
      role: "APK 静态门禁和二次扫描",
      artifactPath,
    };
  } catch (error) {
    writeJson(artifactPath, { status: "failed", error: error.message });
    report.pluginStatuses.mobsf = {
      status: "failed",
      role: "APK 静态门禁和二次扫描",
      artifactPath,
      error: error.message,
    };
  }
}

function runLlmIfConfigured(report, options) {
  const reviewInput = buildLlmReviewInput(report);
  writeJson(report.artifacts.llmReviewPath, reviewInput);
  if (!options.llmCommand) {
    return;
  }
  const result = runCommand(options.llmCommand, [], {
    input: JSON.stringify(reviewInput, null, 2),
    timeoutMs: options.llmTimeoutSeconds ? options.llmTimeoutSeconds * 1000 : 120000,
  });
  const artifactPath = path.join(report.artifacts.rootDir, "llm", "review-output.json");
  let parsed = null;
  try {
    parsed = JSON.parse(result.stdout);
  } catch {
    parsed = null;
  }
  writeJson(artifactPath, { status: result.exitCode === 0 ? "completed" : "failed", parsed, result });
  report.pluginStatuses.llm = {
    status: result.exitCode === 0 ? "completed" : "failed",
    role: "证据归纳、字符串解密辅助、规则建议和报告解释",
    artifactPath,
    parsed: Boolean(parsed),
  };
  if (result.exitCode === 0) {
    appendToolFinding(report, {
      id: "llm_review_completed",
      severity: "info",
      score: 10,
      title: "LLM 复核已完成",
      description: "大模型复核输出已落盘；该结果仅作为辅助解释，不能单独判定恶意。",
      evidenceRefs: [artifactPath],
    });
  }
}

function runDynamicIfConfigured(report, options, runtime, samplePath) {
  if (!options.adbAddress || !options.packageName || !runtime.adb) {
    return;
  }
  const artifactPath = path.join(report.artifacts.rootDir, "dynamic", "execution.json");
  const normalized = String(options.adbAddress).replace(/^(?:adb\s+connect\s+|ws:\/\/|wss:\/\/|http:\/\/|https:\/\/)/, "").replace(/\/.*$/, "");
  const events = [];
  const needsConnect = normalized.includes(":");
  const runAdb = (args, name, optional = false) => {
    try {
      const result = runtime.adb.run(args);
      events.push({ name, ok: true, result });
      return result;
    } catch (error) {
      events.push({ name, ok: false, error: error.message, optional });
      if (!optional) {
        throw error;
      }
      return null;
    }
  };
  try {
    if (needsConnect) {
      runAdb(["connect", normalized], "connect");
    } else {
      events.push({ name: "connect", ok: true, skipped: true, reason: "adb serial device does not require adb connect" });
    }
    runAdb(["-s", normalized, "logcat", "-c"], "logcat_clear", true);
    runAdb(["-s", normalized, "install", "-r", samplePath], "install");
    runAdb(["-s", normalized, "shell", "monkey", "-p", options.packageName, "-c", "android.intent.category.LAUNCHER", "1"], "launch");
    runAdb(["-s", normalized, "shell", "logcat", "-d", "-t", "500"], "logcat", true);
    runAdb(["-s", normalized, "shell", "dumpsys", "window"], "dumpsys_window", true);
    runAdb(["-s", normalized, "shell", "screencap", "-p", "/sdcard/testclaw-security-screen.png"], "screencap", true);
    if (options.uninstallAfterDynamic) {
      runAdb(["-s", normalized, "uninstall", options.packageName], "uninstall", true);
    }
    writeJson(artifactPath, { status: "completed", adbAddress: normalized, packageName: options.packageName, events });
    report.pluginStatuses.dynamicExecution = {
      status: "completed",
      role: "TestClaw 设备池动态执行、截图、logcat、流量和 DEX dump",
      artifactPath,
    };
    appendToolFinding(report, {
      id: "dynamic_execution_completed",
      severity: "info",
      score: 10,
      title: "ADB 动态执行已完成",
      description: "样本已在指定 Android 设备上完成安装、启动和基础日志/窗口采集。",
      evidenceRefs: [artifactPath],
    });
  } catch (error) {
    writeJson(artifactPath, { status: "failed", adbAddress: normalized, packageName: options.packageName, events, error: error.message });
    report.pluginStatuses.dynamicExecution = {
      status: "failed",
      role: "TestClaw 设备池动态执行、截图、logcat、流量和 DEX dump",
      artifactPath,
      error: error.message,
    };
  }
}

function runFridaDexIfConfigured(report, options) {
  if (!options.fridaDexCommand && !options.fridaDexArtifact) {
    return;
  }
  const artifactPath = path.join(report.artifacts.rootDir, "dex", "frida-dexdump.json");
  if (options.fridaDexArtifact) {
    const sourcePath = path.resolve(options.fridaDexArtifact);
    const exists = fs.existsSync(sourcePath);
    const payload = {
      status: exists ? "completed" : "failed",
      mode: "imported_artifact",
      sourcePath,
      artifact: exists ? artifactEntry("frida_dex_artifact", sourcePath, report.artifacts.rootDir) : null,
      error: exists ? null : `Frida/DEX artifact not found: ${sourcePath}`,
    };
    writeJson(artifactPath, payload);
    report.pluginStatuses.fridaDex = {
      status: payload.status,
      role: "Frida Hook 与运行期 DEX dump",
      artifactPath,
      sourcePath,
      error: payload.error,
    };
  } else {
    const result = runCommand(options.fridaDexCommand, [], {
      input: JSON.stringify({
        sample: report.sample,
        packageName: options.packageName || null,
        adbAddress: options.adbAddress || null,
        outDir: path.join(report.artifacts.rootDir, "dex"),
      }, null, 2),
      timeoutMs: options.fridaDexTimeoutSeconds ? options.fridaDexTimeoutSeconds * 1000 : defaultEngineTimeoutMs("fridaDex"),
    });
    const payload = { status: result.exitCode === 0 ? "completed" : "failed", mode: "command", result };
    writeJson(artifactPath, payload);
    report.pluginStatuses.fridaDex = {
      status: payload.status,
      role: "Frida Hook 与运行期 DEX dump",
      artifactPath,
    };
  }
  if (report.pluginStatuses.fridaDex.status === "completed") {
    appendToolFinding(report, {
      id: "frida_dex_evidence_collected",
      severity: "info",
      score: 10,
      title: "Frida/DEX 运行期证据已采集",
      description: "运行期 DEX dump 或 Frida Hook 产物已纳入安全分析报告，可用于动态加载和字符串解密复核。",
      evidenceRefs: [artifactPath],
    });
  }
}

function runMitmPcapIfConfigured(report, options) {
  if (!options.mitmCommand && !options.mitmPcapPath) {
    return;
  }
  const artifactPath = path.join(report.artifacts.rootDir, "network", "mitm-pcap.json");
  if (options.mitmPcapPath) {
    const sourcePath = path.resolve(options.mitmPcapPath);
    const exists = fs.existsSync(sourcePath);
    const payload = {
      status: exists ? "completed" : "failed",
      mode: "imported_artifact",
      sourcePath,
      artifact: exists ? artifactEntry("mitm_pcap_artifact", sourcePath, report.artifacts.rootDir) : null,
      error: exists ? null : `MITM/PCAP artifact not found: ${sourcePath}`,
    };
    writeJson(artifactPath, payload);
    report.pluginStatuses.mitmPcap = {
      status: payload.status,
      role: "MITM/PCAP 真实流量采集",
      artifactPath,
      sourcePath,
      error: payload.error,
    };
  } else {
    const result = runCommand(options.mitmCommand, [], {
      input: JSON.stringify({
        sample: report.sample,
        packageName: options.packageName || null,
        adbAddress: options.adbAddress || null,
        outDir: path.join(report.artifacts.rootDir, "network"),
        iocs: report.iocs,
      }, null, 2),
      timeoutMs: options.mitmPcapTimeoutSeconds ? options.mitmPcapTimeoutSeconds * 1000 : defaultEngineTimeoutMs("mitmPcap"),
    });
    const payload = { status: result.exitCode === 0 ? "completed" : "failed", mode: "command", result };
    writeJson(artifactPath, payload);
    report.pluginStatuses.mitmPcap = {
      status: payload.status,
      role: "MITM/PCAP 真实流量采集",
      artifactPath,
    };
  }
  if (report.pluginStatuses.mitmPcap.status === "completed") {
    appendToolFinding(report, {
      id: "mitm_pcap_evidence_collected",
      severity: "info",
      score: 10,
      title: "MITM/PCAP 流量证据已采集",
      description: "真实网络流量或 PCAP 产物已纳入安全分析报告，可用于 IOC 和外联行为复核。",
      evidenceRefs: [artifactPath],
    });
  }
}

function buildLlmReviewInput(report) {
  return {
    task: "android_adware_analysis_review",
    instructions: [
      "只基于 evidenceRefs、findings、iocs 和 artifacts 做归纳，不要凭空定罪。",
      "重点分析加密字符串候选、动态加载线索、悬浮窗弹窗线索和网络 IOC。",
      "输出 JSON，包含 summary、suspected_behaviors、string_decryption_plan、rule_suggestions、manual_review。",
    ],
    sample: report.sample,
    risk: report.risk,
    findings: report.findings,
    iocs: report.iocs,
    pluginStatuses: report.pluginStatuses,
  };
}

const EXTERNAL_ENGINE_ADAPTERS = [
  { engine: "yara", stage: "yara_scan", run: (context) => runYaraIfConfigured(context.report, context.options, context.samplePath) },
  { engine: "quark", stage: "quark_behavior_chain", run: (context) => runQuarkIfConfigured(context.report, context.options, context.samplePath) },
  { engine: "mobsf", stage: "mobsf_static_gate", run: (context) => runMobsfIfConfigured(context.report, context.options, context.samplePath) },
  { engine: "dynamicExecution", stage: "dynamic_execution", run: (context) => runDynamicIfConfigured(context.report, context.options, context.runtime, context.samplePath) },
  { engine: "fridaDex", stage: "dex_capture", run: (context) => runFridaDexIfConfigured(context.report, context.options, context.samplePath) },
  { engine: "mitmPcap", stage: "network_capture", run: (context) => runMitmPcapIfConfigured(context.report, context.options, context.samplePath) },
  { engine: "llm", stage: "llm_review", run: (context) => runLlmIfConfigured(context.report, context.options) },
];

async function runExternalEngineAdapters(report, options, runtime, samplePath) {
  for (const adapter of EXTERNAL_ENGINE_ADAPTERS) {
    await adapter.run({ report, options, runtime, samplePath });
    const status = report.pluginStatuses[adapter.engine] || {};
    setStageStatus(report, adapter.stage, status.status, {
      artifactPath: status.artifactPath,
      adapter: adapter.engine,
    });
  }
}

async function analyzeSecuritySample(options, runtime = {}) {
  const sample = readSample(options.filePath);
  const outRoot = path.resolve(options.outDir || path.join(process.cwd(), "security-artifacts"));
  const sampleDir = path.join(outRoot, sample.hash);
  const directories = ["mobsf", "dynamic", "dex", "yara", "quark", "network", "screenshots", "logs", "llm", "rules", "strings"];
  for (const directory of directories) {
    fs.mkdirSync(path.join(sampleDir, directory), { recursive: true });
  }
  fs.mkdirSync(sampleDir, { recursive: true });

  const iocs = extractIocs(sample.text);
  const scored = scoreStaticEvidence(sample.text, iocs);
  const reportPath = path.join(sampleDir, "report.json");
  const llmReviewPath = path.join(sampleDir, "llm", "review-input.json");
  const sampleCopyPath = path.join(sampleDir, "original.apk");
  const manifestPath = path.join(sampleDir, "artifact-manifest.json");
  const timelinePath = path.join(sampleDir, "evidence-timeline.json");
  const stringCandidatesPath = path.join(sampleDir, "strings", "decryption-candidates.json");
  const ruleSuggestionsPath = path.join(sampleDir, "rules", "suggestions.json");
  const htmlReportPath = path.join(sampleDir, "report.html");

  if (!fs.existsSync(sampleCopyPath)) {
    fs.copyFileSync(sample.absolutePath, sampleCopyPath);
  }

  const report = {
    ok: true,
    generatedAt: new Date().toISOString(),
    pipeline: {
      name: "android-hybrid-adware-analysis",
      implementation: "testclaw-security-cli-engineering",
      sourceDocument: "docs/android-hybrid-adware-analysis-pipeline.html",
      profile: options.profile || "adware-static-mvp",
      stages: buildPipelineStages(),
    },
    sample: {
      sha256: sample.hash,
      fileName: path.basename(sample.absolutePath),
      originalPath: sample.absolutePath,
      artifactPath: sampleCopyPath,
      sizeBytes: sample.stat.size,
    },
    risk: {
      score: scored.score,
      level: scored.level,
      label: scored.label,
      model: "testclaw_static_mvp_v1",
    },
    findings: scored.findings,
    iocs,
    pluginStatuses: buildPluginStatuses(),
    artifacts: {
      rootDir: sampleDir,
      reportPath,
      llmReviewPath,
      sampleCopyPath,
      manifestPath,
      timelinePath,
      stringCandidatesPath,
      ruleSuggestionsPath,
      htmlReportPath,
    },
    completion: {
      completedLocally: [
        "样本登记与 SHA256 去重",
        "本地静态风险评分",
        "URL/域名/IP/包名/加密字符串候选提取",
        "LLM 复核输入包生成",
        "统一 JSON 报告生成",
      ],
      requiresExternalRuntime: [
        "MobSF REST API 静态报告",
        "YARA 规则扫描",
        "Quark-Engine 行为链扫描",
        "TestClaw 设备池动态执行",
        "Frida Hook / frida-dexdump",
        "MITM/PCAP 真实流量采集",
        "企业 LLM Gateway 复核",
      ],
    },
  };
  setStageStatus(report, "sample_registration", "completed", { artifactPath: sampleCopyPath });
  setStageStatus(report, "static_triage", "completed", { findingCount: report.findings.length });
  setStageStatus(report, "string_decryption", "completed", { candidateCount: Object.values(iocs.encryptedStringCandidates).reduce((sum, values) => sum + values.length, 0) });

  await runExternalEngineAdapters(report, options, runtime, sampleCopyPath);
  normalizePluginStatuses(report, options);
  refreshRiskLevel(report);
  report.stringDecryption = buildStringDecryptionPlan(report);
  report.ruleSuggestions = buildRuleSuggestions(report);
  report.evidenceTimeline = buildEvidenceTimeline(report);
  setStageStatus(report, "reporting", "completed", { artifactPath: reportPath });
  writeJson(stringCandidatesPath, report.stringDecryption);
  writeJson(ruleSuggestionsPath, report.ruleSuggestions);
  writeJson(timelinePath, report.evidenceTimeline);
  writeText(htmlReportPath, buildHtmlReport(report));
  writeJson(manifestPath, buildArtifactIndex(report));
  writeJson(reportPath, report);
  writeJson(llmReviewPath, buildLlmReviewInput(report));
  writeJson(manifestPath, buildArtifactIndex(report));
  return report;
}

function readSecurityReport(reportPath) {
  return JSON.parse(fs.readFileSync(path.resolve(reportPath), "utf8"));
}

function readSecurityIocs(reportPath) {
  const report = readSecurityReport(reportPath);
  return {
    sample: report.sample,
    risk: report.risk,
    ...report.iocs,
  };
}

function readSecurityArtifacts(reportPath) {
  return buildArtifactIndex(readSecurityReport(reportPath));
}

function validateSecurityReport(reportPath) {
  return validateSecurityReportPayload(readSecurityReport(reportPath));
}

module.exports = {
  analyzeSecuritySample,
  extractIocs,
  readSecurityArtifacts,
  readSecurityIocs,
  readSecurityReport,
  scoreStaticEvidence,
  validateSecurityReport,
};

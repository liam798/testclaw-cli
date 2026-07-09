const readline = require("node:readline");
const { formatJson, formatText } = require("./formatter");
const { CommandSession } = require("./session");
const { LocalAdbBackend } = require("./adb-backend");
const { oauthLogin } = require("./oauth-client");
const {
  analyzeSecuritySample,
  readSecurityArtifacts,
  readSecurityIocs,
  readSecurityReport,
  validateSecurityReport,
} = require("./security-analysis");
const { buildConfig, SonicBackend, inferOAuthBaseUrl } = require("./sonic-backend");
const { PUBLIC_CONFIG_KEYS, configToPublicKeyValue, normalizeConfigValue } = require("./config");
const { SonicCliError } = require("./errors");
const pkg = require("../package.json");

function rootHelp() {
  return `TestClaw - Automation testing with AI orchestration

用法:
  testclaw [全局选项] <命令> [子命令] [选项]

全局选项:
  --json / --no-json
  -h, --help

命令:
  doctor
  login
  logout
  whoami
  config list|get|set|unset
  project list
  module create
  case create
  step create
  device list|prepare-android-debug|release
  app list-installed|install|open|kill|uninstall
  suite create|run
  result get
  package upload
  security analyze|report|ioc|artifacts|validate|task
  zentao project|product|binding|case|step-mapping|result|bug
  ai case-generate|bug-generate|job
  agent report
  raw request
  session show|undo|redo`;
}

function configHelp() {
  return `用法:
  testclaw config list
  testclaw config get <key>
  testclaw config set <key> <value>
  testclaw config unset <key>

配置项:
  base_url
  adb_bin`;
}

function assertConfigKey(key) {
  const definition = PUBLIC_CONFIG_KEYS[key];
  if (!definition) {
    throw new SonicCliError(`未知配置项: ${key}`);
  }
  return definition;
}

function readConfigValue(app, key) {
  const definition = assertConfigKey(key);
  return app.backend.config[definition.field] ?? "";
}

function writeConfigValue(app, key, value) {
  const definition = assertConfigKey(key);
  const normalized = normalizeConfigValue(key, value);
  app.backend.config[definition.field] = normalized;
  if (key === "adb_bin") {
    app.adb = new LocalAdbBackend(normalized);
  }
  return normalized;
}

function unsetConfigValue(app, key) {
  const definition = assertConfigKey(key);
  const store = definition.scope === "auth" ? app.backend.authStore : app.backend.configStore;
  const payload = store.load();
  delete payload[key];
  delete payload[definition.legacyKey];
  store.save(payload);
}

function parseShellArgs(input) {
  const result = [];
  let current = "";
  let quote = null;
  let escaped = false;
  for (const char of input) {
    if (escaped) {
      current += char;
      escaped = false;
      continue;
    }
    if (char === "\\") {
      escaped = true;
      continue;
    }
    if (quote) {
      if (char === quote) {
        quote = null;
      } else {
        current += char;
      }
      continue;
    }
    if (char === "'" || char === "\"") {
      quote = char;
      continue;
    }
    if (/\s/.test(char)) {
      if (current) {
        result.push(current);
        current = "";
      }
      continue;
    }
    current += char;
  }
  if (current) {
    result.push(current);
  }
  return result;
}

function parseGlobalOptions(argv) {
  const options = {};
  const remaining = [];
  let parsingGlobals = true;
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (parsingGlobals && !arg.startsWith("-")) {
      parsingGlobals = false;
      remaining.push(arg);
      continue;
    }
    if (!parsingGlobals) {
      remaining.push(arg);
      continue;
    }
    if (arg === "--json") {
      options.jsonOutput = true;
    } else if (arg === "--no-json") {
      options.jsonOutput = false;
    } else if (arg === "-h" || arg === "--help") {
      options.help = true;
    } else {
      throw new SonicCliError(`未知全局选项: ${arg}`);
    }
  }
  return { options, remaining };
}

function parseCommandOptions(argv, schema) {
  const options = {};
  for (const [name, config] of Object.entries(schema)) {
    if (config.default !== undefined) {
      options[name] = config.default;
    }
    if (config.multiple) {
      options[name] = [];
    }
  }

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "-h" || arg === "--help") {
      options.help = true;
      continue;
    }
    const entry = Object.entries(schema).find(([, config]) => config.flag === arg || config.noFlag === arg);
    if (!entry) {
      throw new SonicCliError(`未知选项: ${arg}`);
    }
    const [name, config] = entry;
    if (config.type === "boolean") {
      options[name] = arg === config.noFlag ? false : true;
      continue;
    }
    const value = argv[++index];
    if (value === undefined) {
      throw new SonicCliError(`选项 ${arg} 缺少值。`);
    }
    const normalized = config.type === "number" ? Number(value) : value;
    if (config.type === "number" && Number.isNaN(normalized)) {
      throw new SonicCliError(`选项 ${arg} 需要数字。`);
    }
    if (config.multiple) {
      options[name].push(normalized);
    } else {
      options[name] = normalized;
    }
  }

  for (const [name, config] of Object.entries(schema)) {
    if (config.required && (options[name] === undefined || options[name] === null || options[name] === "" || (Array.isArray(options[name]) && !options[name].length))) {
      throw new SonicCliError(`缺少必填选项 ${config.flag}。`);
    }
  }
  return options;
}

function parseJsonOption(value, label) {
  try {
    return JSON.parse(value || "null");
  } catch (error) {
    throw new SonicCliError(`${label} 不是合法 JSON: ${error.message}`);
  }
}

function buildApp(globalOptions) {
  const { config, configStore, authStore } = buildConfig(globalOptions);
  return {
    jsonOutput: Boolean(globalOptions.jsonOutput),
    backend: new SonicBackend(config, configStore, authStore),
    adb: new LocalAdbBackend(config.adbBin),
    session: new CommandSession(),
  };
}

function emit(app, payload) {
  process.stdout.write(`${app.jsonOutput ? formatJson(payload) : formatText(payload)}\n`);
}

function resolveAdbAddress(app, adbAddress) {
  if (adbAddress) {
    return adbAddress;
  }
  if (app.session.selectedAdbAddress) {
    return app.session.selectedAdbAddress;
  }
  throw new SonicCliError("缺少 --adb-address，且当前会话没有已准备的 adb 地址。");
}

async function runRepl(app) {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
    prompt: "testclaw> ",
  });
  rl.prompt();
  for await (const line of rl) {
    const trimmed = line.trim();
    if (!trimmed) {
      rl.prompt();
      continue;
    }
    if (trimmed === "exit" || trimmed === "quit") {
      rl.close();
      break;
    }
    if (trimmed === "help") {
      process.stdout.write(`${rootHelp()}\n`);
      rl.prompt();
      continue;
    }
    try {
      await dispatch(app, parseShellArgs(trimmed));
    } catch (error) {
      process.stderr.write(`${error.message}\n`);
    }
    rl.prompt();
  }
}

async function dispatch(app, argv) {
  const command = argv[0];
  const subcommand = argv[1];
  const commandArgs = argv.slice(1);
  const subcommandArgs = argv.slice(2);
  if (!command) {
    await runRepl(app);
    return;
  }
  if (command === "doctor") {
    emit(app, await app.backend.doctor({ version: pkg.version }));
    return;
  }
  if (command === "whoami") {
    emit(app, await app.backend.getCurrentUser());
    return;
  }
  if (command === "logout") {
    emit(app, app.backend.clearAuth());
    return;
  }
  if (command === "login") {
    const options = parseCommandOptions(commandArgs, {
      username: { flag: "--username" },
      password: { flag: "--password" },
      browserCommand: { flag: "--browser-command" },
      listenHost: { flag: "--listen-host", default: "127.0.0.1" },
      listenPort: { flag: "--listen-port", type: "number", default: 0 },
      timeoutSeconds: { flag: "--timeout-seconds", type: "number", default: 180 },
    });
    if (options.help) {
      process.stdout.write(`用法:
  testclaw login
  testclaw login --username <name> --password <password>

默认打开 TestClaw 统一登录页，支持 MemHub 登录；--username/--password 仅作为本地账号直连备用。
`);
      return;
    }
    if (options.username || options.password) {
      if (!options.username || !options.password) {
        throw new SonicCliError("直连登录需要同时提供 --username 和 --password。");
      }
      emit(app, await app.backend.login(options.username, options.password));
      return;
    }
    const oauthBaseUrl = inferOAuthBaseUrl(app.backend.config.baseUrl);
    const result = await oauthLogin({
      oauthBaseUrl,
      browserCommand: options.browserCommand,
      listenHost: options.listenHost,
      listenPort: options.listenPort,
      timeoutSeconds: options.timeoutSeconds,
    });
    app.backend.config.token = result.session.sonicToken;
    app.backend.config.oauthAccessToken = result.access_token;
    app.backend.config.oauthRefreshToken = result.refresh_token || null;
    app.backend.config.oauthClientId = result.client_id;
    app.backend.saveRuntimeConfig();
    emit(app, result);
    return;
  }

  if (command === "config" && (subcommand === "-h" || subcommand === "--help")) {
    process.stdout.write(`${configHelp()}\n`);
    return;
  }

  if (command === "config" && subcommand === "list") {
    emit(app, configToPublicKeyValue(app.backend.config));
    return;
  }

  if (command === "config" && subcommand === "get") {
    const key = subcommandArgs[0];
    if (!key) {
      throw new SonicCliError("缺少配置项名称。");
    }
    emit(app, readConfigValue(app, key));
    return;
  }

  if (command === "config" && subcommand === "unset") {
    const key = subcommandArgs[0];
    if (!key) {
      throw new SonicCliError("缺少配置项名称。");
    }
    const definition = assertConfigKey(key);
    unsetConfigValue(app, key);
    app.backend.config[definition.field] = definition.defaultValue;
    emit(app, configToPublicKeyValue(app.backend.config));
    return;
  }

  if (command === "config" && subcommand === "set") {
    if (subcommandArgs.length === 2 && !subcommandArgs[0].startsWith("-")) {
      writeConfigValue(app, subcommandArgs[0], subcommandArgs[1]);
      app.backend.saveRuntimeConfig();
      return;
    }
    throw new SonicCliError("用法: testclaw config set <key> <value>");
  }

  if (command === "config") {
    if (!subcommand) {
      process.stdout.write(`${configHelp()}\n`);
      return;
    }
    throw new SonicCliError(`未知 config 子命令: ${subcommand}`);
  }

  if (command === "project" && subcommand === "list") {
    emit(app, await app.backend.listProjects());
    return;
  }

  if (command === "module" && subcommand === "create") {
    const options = parseCommandOptions(subcommandArgs, {
      moduleId: { flag: "--id", type: "number" },
      projectId: { flag: "--project-id", type: "number", required: true },
      name: { flag: "--name", required: true },
    });
    emit(app, await app.backend.createModule(options));
    return;
  }

  if (command === "case" && subcommand === "create") {
    const options = parseCommandOptions(subcommandArgs, {
      caseId: { flag: "--id", type: "number" },
      projectId: { flag: "--project-id", type: "number", required: true },
      platform: { flag: "--platform", type: "number", required: true },
      name: { flag: "--name", required: true },
      moduleId: { flag: "--module-id", type: "number", default: 0 },
      version: { flag: "--version", default: "" },
      des: { flag: "--des", default: "" },
      zentaoCaseLinkId: { flag: "--zentao-case-link-id", type: "number" },
      zentaoCaseId: { flag: "--zentao-case-id", type: "number" },
      zentaoCaseTitle: { flag: "--zentao-case-title" },
      zentaoProductId: { flag: "--zentao-product-id", type: "number" },
    });
    emit(app, await app.backend.createTestCase(options));
    return;
  }

  if (command === "step" && subcommand === "create") {
    const options = parseCommandOptions(subcommandArgs, {
      stepId: { flag: "--id", type: "number" },
      projectId: { flag: "--project-id", type: "number", required: true },
      platform: { flag: "--platform", type: "number", required: true },
      stepType: { flag: "--step-type", required: true },
      caseId: { flag: "--case-id", type: "number" },
      publicStepsId: { flag: "--public-steps-id", type: "number" },
      parentId: { flag: "--parent-id", type: "number", default: 0 },
      content: { flag: "--content", default: "" },
      text: { flag: "--text", default: "" },
      error: { flag: "--error", type: "number", default: 3 },
      conditionType: { flag: "--condition-type", type: "number", default: 0 },
      disabled: { flag: "--disabled", type: "number", default: 0 },
      elementIds: { flag: "--element-id", type: "number", multiple: true },
    });
    emit(app, await app.backend.createStep(options));
    return;
  }

  if (command === "device" && subcommand === "list") {
    const options = parseCommandOptions(subcommandArgs, {
      page: { flag: "--page", type: "number", default: 1 },
      pageSize: { flag: "--page-size", type: "number", default: 20 },
      deviceInfo: { flag: "--device-info" },
      status: { flag: "--status", multiple: true },
    });
    emit(app, await app.backend.listDevices(options));
    return;
  }

  if (command === "device" && subcommand === "prepare-android-debug") {
    const options = parseCommandOptions(subcommandArgs, {
      deviceId: { flag: "--device-id", type: "number" },
      udid: { flag: "--udid" },
      sasRemotePort: { flag: "--sas-remote-port", type: "number" },
      uia2RemotePort: { flag: "--uia2-remote-port", type: "number" },
    });
    const selector = { deviceId: options.deviceId, udId: options.udid };
    const result = await app.backend.prepareAndroidDebug(options);
    app.session.rememberPrepare(selector, result);
    emit(app, result);
    return;
  }

  if (command === "device" && subcommand === "release") {
    const options = parseCommandOptions(subcommandArgs, {
      deviceId: { flag: "--device-id", type: "number" },
      udid: { flag: "--udid" },
      adbAddress: { flag: "--adb-address" },
    });
    if (!options.deviceId && !options.udid && app.session.selectedDevice) {
      options.deviceId = app.session.selectedDevice.deviceId;
      options.udid = app.session.selectedDevice.udId;
    }
    const result = await app.backend.releaseDevice(options);
    app.session.rememberIrreversible("release_device", result, {
      selector: { deviceId: options.deviceId, udId: options.udid },
    });
    emit(app, result);
    return;
  }

  if (command === "app" && subcommand === "list-installed") {
    const options = parseCommandOptions(subcommandArgs, {
      adbAddress: { flag: "--adb-address" },
    });
    const result = app.adb.listInstalledApps(resolveAdbAddress(app, options.adbAddress));
    app.session.rememberIrreversible("list_installed_apps", result);
    emit(app, result);
    return;
  }

  if (command === "app" && subcommand === "install") {
    const options = parseCommandOptions(subcommandArgs, {
      adbAddress: { flag: "--adb-address" },
      packageUrl: { flag: "--package-url", required: true },
    });
    const result = await app.adb.installPackage(resolveAdbAddress(app, options.adbAddress), options.packageUrl);
    app.session.rememberIrreversible("install_app", result, { packageUrl: options.packageUrl });
    emit(app, result);
    return;
  }

  if (command === "app" && subcommand === "open") {
    const options = parseCommandOptions(subcommandArgs, {
      adbAddress: { flag: "--adb-address" },
      appId: { flag: "--app-id", required: true },
    });
    const adbAddress = resolveAdbAddress(app, options.adbAddress);
    const result = app.adb.openApp(adbAddress, options.appId);
    app.session.rememberOpenApp(adbAddress, options.appId, result);
    emit(app, result);
    return;
  }

  if (command === "app" && subcommand === "kill") {
    const options = parseCommandOptions(subcommandArgs, {
      adbAddress: { flag: "--adb-address" },
      appId: { flag: "--app-id", required: true },
    });
    const result = app.adb.killApp(resolveAdbAddress(app, options.adbAddress), options.appId);
    app.session.rememberIrreversible("kill_app", result, { appId: options.appId });
    emit(app, result);
    return;
  }

  if (command === "app" && subcommand === "uninstall") {
    const options = parseCommandOptions(subcommandArgs, {
      adbAddress: { flag: "--adb-address" },
      appId: { flag: "--app-id", required: true },
    });
    const result = app.adb.uninstallApp(resolveAdbAddress(app, options.adbAddress), options.appId);
    app.session.rememberIrreversible("uninstall_app", result, { appId: options.appId });
    emit(app, result);
    return;
  }

  if (command === "suite" && subcommand === "create") {
    const options = parseCommandOptions(subcommandArgs, {
      suiteId: { flag: "--id", type: "number" },
      projectId: { flag: "--project-id", type: "number", required: true },
      platform: { flag: "--platform", type: "number", required: true },
      name: { flag: "--name", required: true },
      cover: { flag: "--cover", type: "number", required: true },
      isOpenPerfmon: { flag: "--is-open-perfmon", type: "number", default: 0 },
      perfmonInterval: { flag: "--perfmon-interval", type: "number", default: 1000 },
      deviceIds: { flag: "--device-id", type: "number", multiple: true },
      testCaseIds: { flag: "--test-case-id", type: "number", multiple: true },
      alertRobotIds: { flag: "--alert-robot-id", type: "number", multiple: true },
    });
    if (!options.alertRobotIds.length) {
      options.alertRobotIds = null;
    }
    emit(app, await app.backend.createSuite(options));
    return;
  }

  if (command === "suite" && subcommand === "run") {
    const options = parseCommandOptions(subcommandArgs, {
      suiteId: { flag: "--id", type: "number", required: true },
    });
    emit(app, await app.backend.runSuite(options.suiteId));
    return;
  }

  if (command === "result" && subcommand === "get") {
    const options = parseCommandOptions(subcommandArgs, {
      resultId: { flag: "--id", type: "number", required: true },
    });
    emit(app, await app.backend.getResult(options.resultId));
    return;
  }

  if (command === "package" && subcommand === "upload") {
    const options = parseCommandOptions(subcommandArgs, {
      filePath: { flag: "--file", required: true },
      projectId: { flag: "--project-id", type: "number", required: true },
      pkgName: { flag: "--pkg-name", required: true },
      platform: { flag: "--platform", required: true },
      branch: { flag: "--branch", required: true },
      buildUrl: { flag: "--build-url" },
      typeName: { flag: "--type", default: "packageFiles" },
    });
    emit(app, await app.backend.uploadPackage(options));
    return;
  }

  if (command === "security" && subcommand === "analyze") {
    const options = parseCommandOptions(subcommandArgs, {
      filePath: { flag: "--file", required: true },
      outDir: { flag: "--out-dir" },
      profile: { flag: "--profile", default: "adware-static-mvp" },
      yaraBin: { flag: "--yara-bin" },
      yaraRules: { flag: "--yara-rules" },
      quarkBin: { flag: "--quark-bin" },
      quarkRules: { flag: "--quark-rules" },
      quarkTimeoutSeconds: { flag: "--quark-timeout-seconds", type: "number" },
      mobsfUrl: { flag: "--mobsf-url" },
      mobsfKey: { flag: "--mobsf-key" },
      fridaDexCommand: { flag: "--frida-dex-command" },
      fridaDexArtifact: { flag: "--frida-dex-artifact" },
      fridaDexTimeoutSeconds: { flag: "--frida-dex-timeout-seconds", type: "number" },
      mitmCommand: { flag: "--mitm-command" },
      mitmPcapPath: { flag: "--mitm-pcap-path" },
      mitmPcapTimeoutSeconds: { flag: "--mitm-pcap-timeout-seconds", type: "number" },
      llmCommand: { flag: "--llm-command" },
      llmTimeoutSeconds: { flag: "--llm-timeout-seconds", type: "number" },
      adbAddress: { flag: "--adb-address" },
      packageName: { flag: "--package-name" },
      uninstallAfterDynamic: { flag: "--uninstall-after-dynamic", noFlag: "--no-uninstall-after-dynamic", type: "boolean", default: false },
    });
    emit(app, await analyzeSecuritySample(options, { adb: app.adb }));
    return;
  }

  if (command === "security" && subcommand === "task") {
    const action = subcommandArgs[0];
    const args = subcommandArgs.slice(1);
    if (action === "create") {
      const options = parseCommandOptions(args, {
        projectId: { flag: "--project-id", type: "number", required: true },
        sampleSha256: { flag: "--sample-sha256", required: true },
        packageName: { flag: "--package-name" },
        profile: { flag: "--profile", default: "adware-deep" },
        deviceUdid: { flag: "--device-udid" },
      });
      emit(app, await app.backend.createSecurityTask(options));
      return;
    }
    if (action === "list") {
      const options = parseCommandOptions(args, {
        projectId: { flag: "--project-id", type: "number", required: true },
      });
      emit(app, await app.backend.listSecurityTasks(options));
      return;
    }
    if (action === "ingest-report") {
      const options = parseCommandOptions(args, {
        taskId: { flag: "--task-id", type: "number", required: true },
        reportPath: { flag: "--report", required: true },
      });
      const report = readSecurityReport(options.reportPath);
      emit(app, await app.backend.ingestSecurityReport(options.taskId, report));
      return;
    }
    if (action === "report") {
      const options = parseCommandOptions(args, {
        taskId: { flag: "--task-id", type: "number", required: true },
      });
      emit(app, await app.backend.getSecurityReport(options.taskId));
      return;
    }
    throw new SonicCliError("用法: testclaw security task create|list|ingest-report|report ...");
  }

  if (command === "security" && subcommand === "report") {
    const options = parseCommandOptions(subcommandArgs, {
      reportPath: { flag: "--report", required: true },
    });
    emit(app, readSecurityReport(options.reportPath));
    return;
  }

  if (command === "security" && subcommand === "ioc") {
    const options = parseCommandOptions(subcommandArgs, {
      reportPath: { flag: "--report", required: true },
    });
    emit(app, readSecurityIocs(options.reportPath));
    return;
  }

  if (command === "security" && subcommand === "artifacts") {
    const options = parseCommandOptions(subcommandArgs, {
      reportPath: { flag: "--report", required: true },
    });
    emit(app, readSecurityArtifacts(options.reportPath));
    return;
  }

  if (command === "security" && subcommand === "validate") {
    const options = parseCommandOptions(subcommandArgs, {
      reportPath: { flag: "--report", required: true },
    });
    emit(app, validateSecurityReport(options.reportPath));
    return;
  }

  if (command === "security") {
    throw new SonicCliError(`未知 security 子命令: ${subcommand || ""}`.trim());
  }

  if (command === "zentao" && subcommand === "project") {
    const action = subcommandArgs[0];
    const args = subcommandArgs.slice(1);
    if (action !== "list") {
      throw new SonicCliError("用法: testclaw zentao project list [--keyword <kw>] [--limit <n>]");
    }
    const options = parseCommandOptions(args, {
      keyword: { flag: "--keyword" },
      limit: { flag: "--limit", type: "number" },
    });
    emit(app, await app.backend.listZentaoProjects(options));
    return;
  }

  if (command === "zentao" && subcommand === "product") {
    const action = subcommandArgs[0];
    const args = subcommandArgs.slice(1);
    if (action !== "search") {
      throw new SonicCliError("用法: testclaw zentao product search [--keyword <kw>] [--limit <n>]");
    }
    const options = parseCommandOptions(args, {
      keyword: { flag: "--keyword" },
      limit: { flag: "--limit", type: "number" },
    });
    emit(app, await app.backend.searchZentaoProducts(options));
    return;
  }

  if (command === "zentao" && subcommand === "binding") {
    const action = subcommandArgs[0];
    const args = subcommandArgs.slice(1);
    if (action === "get") {
      const options = parseCommandOptions(args, {
        projectId: { flag: "--project-id", type: "number", required: true },
      });
      emit(app, await app.backend.getZentaoBindings(options.projectId));
      return;
    }
    if (action === "set") {
      const options = parseCommandOptions(args, {
        id: { flag: "--id", type: "number" },
        projectId: { flag: "--project-id", type: "number", required: true },
        zentaoProjectId: { flag: "--zentao-project-id", type: "number" },
        zentaoProjectName: { flag: "--zentao-project-name" },
        zentaoProductId: { flag: "--zentao-product-id", type: "number" },
        zentaoProductName: { flag: "--zentao-product-name" },
        zentaoExecutionId: { flag: "--zentao-execution-id", type: "number" },
        defaultBugSeverity: { flag: "--default-bug-severity", type: "number", default: 3 },
        defaultBugType: { flag: "--default-bug-type", default: "codeerror" },
        defaultAssignee: { flag: "--default-assignee" },
        autoSubmitBug: { flag: "--auto-submit-bug", noFlag: "--no-auto-submit-bug", type: "boolean" },
        zentaoWarnResult: { flag: "--zentao-warn-result" },
      });
      emit(app, await app.backend.saveZentaoBinding(options));
      return;
    }
    throw new SonicCliError("用法: testclaw zentao binding get|set ...");
  }

  if (command === "zentao" && subcommand === "case") {
    const action = subcommandArgs[0];
    const args = subcommandArgs.slice(1);
    if (action === "list") {
      const options = parseCommandOptions(args, {
        caseId: { flag: "--case-id", type: "number", required: true },
      });
      emit(app, await app.backend.listZentaoCaseLinks(options.caseId));
      return;
    }
    if (action === "get") {
      const options = parseCommandOptions(args, {
        zentaoCaseId: { flag: "--zentao-case-id", type: "number", required: true },
      });
      emit(app, await app.backend.getZentaoTestCase(options.zentaoCaseId));
      return;
    }
    if (action === "link") {
      const options = parseCommandOptions(args, {
        projectId: { flag: "--project-id", type: "number", required: true },
        caseId: { flag: "--case-id", type: "number", required: true },
        zentaoCaseId: { flag: "--zentao-case-id", type: "number" },
        zentaoCaseTitle: { flag: "--zentao-case-title" },
        zentaoProductId: { flag: "--zentao-product-id", type: "number" },
        zentaoModuleId: { flag: "--zentao-module-id", type: "number" },
        sourceType: { flag: "--source-type", default: "manual" },
      });
      emit(app, await app.backend.saveZentaoCaseLink(options));
      return;
    }
    if (action === "unlink") {
      const options = parseCommandOptions(args, {
        id: { flag: "--id", type: "number", required: true },
      });
      emit(app, await app.backend.deleteZentaoCaseLink(options.id));
      return;
    }
    if (action === "import-steps") {
      const options = parseCommandOptions(args, {
        projectId: { flag: "--project-id", type: "number", required: true },
        caseId: { flag: "--case-id", type: "number", required: true },
        zentaoCaseId: { flag: "--zentao-case-id", type: "number", required: true },
        platform: { flag: "--platform", type: "number", required: true },
      });
      emit(app, await app.backend.importZentaoCaseSteps(options));
      return;
    }
    throw new SonicCliError("用法: testclaw zentao case get|link|list|unlink|import-steps ...");
  }

  if (command === "zentao" && subcommand === "step-mapping") {
    const action = subcommandArgs[0];
    const args = subcommandArgs.slice(1);
    if (action === "list") {
      const options = parseCommandOptions(args, {
        caseId: { flag: "--case-id", type: "number", required: true },
        zentaoCaseId: { flag: "--zentao-case-id", type: "number" },
      });
      emit(app, await app.backend.listZentaoCaseStepMappings(options));
      return;
    }
    if (action === "set") {
      const options = parseCommandOptions(args, {
        projectId: { flag: "--project-id", type: "number", required: true },
        caseId: { flag: "--case-id", type: "number", required: true },
        zentaoCaseId: { flag: "--zentao-case-id", type: "number", required: true },
        mappingsJson: { flag: "--mappings-json", required: true },
      });
      const mappings = parseJsonOption(options.mappingsJson, "--mappings-json");
      if (!Array.isArray(mappings)) {
        throw new SonicCliError("--mappings-json 必须是数组。");
      }
      emit(app, await app.backend.saveZentaoCaseStepMappings({
        projectId: options.projectId,
        caseId: options.caseId,
        zentaoCaseId: options.zentaoCaseId,
        mappings,
      }));
      return;
    }
    throw new SonicCliError("用法: testclaw zentao step-mapping list|set ...");
  }

  if (command === "zentao" && subcommand === "result") {
    const action = subcommandArgs[0];
    const args = subcommandArgs.slice(1);
    if (action === "list") {
      const options = parseCommandOptions(args, {
        resultId: { flag: "--result-id", type: "number" },
        caseId: { flag: "--case-id", type: "number" },
      });
      emit(app, await app.backend.listZentaoCaseResultLinks(options));
      return;
    }
    if (action === "retry") {
      const options = parseCommandOptions(args, {
        resultDetailId: { flag: "--result-detail-id", type: "number", required: true },
      });
      emit(app, await app.backend.retryZentaoCaseResult({ resultDetailId: options.resultDetailId }));
      return;
    }
    throw new SonicCliError("用法: testclaw zentao result list|retry ...");
  }

  if (command === "zentao" && subcommand === "bug") {
    const action = subcommandArgs[0];
    const args = subcommandArgs.slice(1);
    if (action === "list") {
      const options = parseCommandOptions(args, {
        resultId: { flag: "--result-id", type: "number" },
        caseId: { flag: "--case-id", type: "number" },
      });
      emit(app, await app.backend.listZentaoBugLinks(options));
      return;
    }
    if (action === "create") {
      const options = parseCommandOptions(args, {
        zentaoProductId: { flag: "--zentao-product-id", type: "number", required: true },
        zentaoProjectId: { flag: "--zentao-project-id", type: "number" },
        resultId: { flag: "--result-id", type: "number" },
        resultDetailId: { flag: "--result-detail-id", type: "number" },
        caseId: { flag: "--case-id", type: "number" },
        deviceId: { flag: "--device-id", type: "number" },
        title: { flag: "--title", required: true },
        severity: { flag: "--severity", type: "number", default: 3 },
        priority: { flag: "--priority", type: "number", default: 3 },
        type: { flag: "--type", default: "codeerror" },
        steps: { flag: "--steps", default: "" },
        failureSignature: { flag: "--failure-signature" },
      });
      emit(app, await app.backend.createZentaoBug(options));
      return;
    }
    if (action === "retry") {
      const options = parseCommandOptions(args, {
        linkId: { flag: "--link-id", type: "number", required: true },
      });
      emit(app, await app.backend.retryZentaoBug(options.linkId));
      return;
    }
    throw new SonicCliError("用法: testclaw zentao bug list|create|retry ...");
  }

  if (command === "ai" && subcommand === "case-generate") {
    const options = parseCommandOptions(subcommandArgs, {
      projectId: { flag: "--project-id", type: "number", required: true },
      filePath: { flag: "--file" },
      text: { flag: "--text" },
      platform: { flag: "--platform", type: "number", default: 1 },
      moduleId: { flag: "--module-id", type: "number", default: 0 },
      sourceTitle: { flag: "--source-title" },
    });
    if (!options.filePath && !options.text) {
      throw new SonicCliError("ai case-generate 需要 --file 或 --text。");
    }
    const sourceContent = options.filePath ? require("node:fs").readFileSync(options.filePath, "utf8") : options.text;
    emit(app, await app.backend.generateAiCases({
      projectId: options.projectId,
      platform: options.platform,
      moduleId: options.moduleId,
      sourceType: options.filePath ? "file" : "text",
      sourceTitle: options.sourceTitle || options.filePath || "命令行输入",
      sourceContent,
    }));
    return;
  }

  if (command === "ai" && subcommand === "bug-generate") {
    const options = parseCommandOptions(subcommandArgs, {
      resultId: { flag: "--result-id", type: "number" },
      resultDetailId: { flag: "--result-detail-id", type: "number" },
      caseId: { flag: "--case-id", type: "number" },
      deviceId: { flag: "--device-id", type: "number" },
      status: { flag: "--status", default: "failed" },
      summary: { flag: "--summary", default: "自动化执行失败" },
      logFile: { flag: "--log-file" },
    });
    const log = options.logFile ? require("node:fs").readFileSync(options.logFile, "utf8") : "";
    emit(app, await app.backend.reportAgentExecution({ ...options, log }));
    return;
  }

  if (command === "ai" && subcommand === "job") {
    const action = subcommandArgs[0];
    const args = subcommandArgs.slice(1);
    if (action === "get") {
      const options = parseCommandOptions(args, {
        id: { flag: "--id", type: "number", required: true },
      });
      emit(app, await app.backend.getAiJob(options.id));
      return;
    }
    if (action === "approve") {
      const options = parseCommandOptions(args, {
        id: { flag: "--id", type: "number", required: true },
        version: { flag: "--version", default: "AI生成" },
        zentaoProductId: { flag: "--zentao-product-id", type: "number" },
      });
      emit(app, await app.backend.approveAiJob(options.id, options));
      return;
    }
    throw new SonicCliError("用法: testclaw ai job get|approve ...");
  }

  if (command === "agent" && subcommand === "report") {
    const options = parseCommandOptions(subcommandArgs, {
      projectId: { flag: "--project-id", type: "number" },
      resultId: { flag: "--result-id", type: "number" },
      caseId: { flag: "--case-id", type: "number" },
      stepId: { flag: "--step-id", type: "number" },
      deviceId: { flag: "--device-id", type: "number" },
      status: { flag: "--status", required: true },
      summary: { flag: "--summary", default: "" },
      logFile: { flag: "--log-file" },
      screenshot: { flag: "--screenshot" },
    });
    const log = options.logFile ? require("node:fs").readFileSync(options.logFile, "utf8") : "";
    emit(app, await app.backend.reportAgentExecution({ ...options, log }));
    return;
  }

  if (command === "raw" && subcommand === "request") {
    const options = parseCommandOptions(subcommandArgs, {
      method: { flag: "--method", default: "GET" },
      path: { flag: "--path", required: true },
      query: { flag: "--query" },
      body: { flag: "--body" },
      auth: { flag: "--auth", noFlag: "--no-auth", type: "boolean", default: true },
    });
    emit(
      app,
      await app.backend.rawRequest(options.method, options.path, {
        query: options.query ? JSON.parse(options.query) : undefined,
        body: options.body ? JSON.parse(options.body) : undefined,
        auth: options.auth,
      }),
    );
    return;
  }

  if (command === "session" && subcommand === "show") {
    emit(app, app.session.snapshot());
    return;
  }
  if (command === "session" && subcommand === "undo") {
    emit(app, await app.session.undo(app));
    return;
  }
  if (command === "session" && subcommand === "redo") {
    emit(app, await app.session.redo(app));
    return;
  }

  throw new SonicCliError(`未知命令: ${[command, subcommand].filter(Boolean).join(" ")}`);
}

async function main(argv = process.argv.slice(2)) {
  const { options, remaining } = parseGlobalOptions(argv);
  if (!remaining.length || (options.help && !remaining.length)) {
    process.stdout.write(`${rootHelp()}\n`);
    return;
  }
  const app = buildApp(options);
  app.jsonOutput = options.jsonOutput === undefined ? false : options.jsonOutput;
  await dispatch(app, remaining);
}

module.exports = {
  buildApp,
  dispatch,
  main,
  parseCommandOptions,
  parseGlobalOptions,
  parseShellArgs,
  rootHelp,
};

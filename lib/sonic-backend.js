const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const { CONFIG_KEYS, buildConfig, configToKeyValue } = require("./config");
const { SonicApiError } = require("./errors");
const {
  clearTestClawSessionFromMemHub,
  readSharedMemHubCredential,
  summarizeSharedMemHubCredentials,
} = require("./memhub-auth");

function inferOAuthBaseUrl(baseUrl) {
  const normalizedBase = String(baseUrl || "").replace(/\/+$/, "");
  if (!normalizedBase) {
    throw new SonicApiError("缺少 base_url，无法推导 OAuth 服务地址。");
  }
  return `${normalizedBase}/api/oauth`;
}

function extractAdbAddress(sasValue) {
  const matched = /adb\s+connect\s+([^\s]+)/.exec(String(sasValue || ""));
  if (!matched) {
    throw new SonicApiError(`无法从返回内容中解析 adb 地址: ${sasValue}`);
  }
  return matched[1].trim();
}

function decodeJwtPayload(token) {
  const value = String(token || "");
  const parts = value.split(".");
  if (parts.length < 2) {
    return null;
  }
  try {
    const normalized = parts[1].replace(/-/g, "+").replace(/_/g, "/");
    const padded = normalized.padEnd(normalized.length + ((4 - (normalized.length % 4)) % 4), "=");
    return JSON.parse(Buffer.from(padded, "base64").toString("utf8"));
  } catch {
    return null;
  }
}

class SonicBackend {
  constructor(config, configStore, authStore) {
    this.config = config;
    this.configStore = configStore;
    this.authStore = authStore;
  }

  buildUrl(resourcePath, query) {
    const normalized = resourcePath.startsWith("/") ? resourcePath : `/${resourcePath}`;
    const base = `${this.config.baseUrl}${this.config.apiPrefix}${normalized}`;
    if (!query) {
      return base;
    }
    const params = new URLSearchParams();
    for (const [key, value] of Object.entries(query)) {
      if (value === undefined || value === null || value === "") {
        continue;
      }
      if (Array.isArray(value)) {
        value.forEach((item) => params.append(key, String(item)));
      } else {
        params.append(key, String(value));
      }
    }
    const queryString = params.toString();
    return queryString ? `${base}?${queryString}` : base;
  }

  buildAbsoluteUrl(resourcePath) {
    const normalized = resourcePath.startsWith("/") ? resourcePath : `/${resourcePath}`;
    return `${this.config.baseUrl}${normalized}`;
  }

  async request(method, resourcePath, { query, body, auth = true, headers = {} } = {}) {
    const requestHeaders = {
      Accept: "application/json",
      ...headers,
    };
    if (auth) {
      Object.assign(requestHeaders, await this.authHeaders());
    }
    let payloadBody = body;
    if (body !== undefined && !(body instanceof FormData)) {
      requestHeaders["Content-Type"] = "application/json";
      payloadBody = JSON.stringify(body);
    }
    const response = await fetch(this.buildUrl(resourcePath, query), {
      method: method.toUpperCase(),
      headers: requestHeaders,
      body: payloadBody,
    });
    const text = await response.text();
    if (!response.ok) {
      throw new SonicApiError(`HTTP ${response.status}: ${text}`);
    }
    const payload = text ? JSON.parse(text) : {};
    if (payload && typeof payload === "object" && ![undefined, null, 2000].includes(payload.code)) {
      throw new SonicApiError(`Sonic 业务错误 ${payload.code}: ${payload.message || "unknown error"}`);
    }
    return payload;
  }

  async ensureAuthenticated() {
    if (this.config.token) {
      return;
    }
    const sharedMemHubCredential = readSharedMemHubCredential(this.config.memhubCredentials);
    if (sharedMemHubCredential) {
      this.config.sharedMemHubCredential = sharedMemHubCredential;
      this.config.authMode = "memhub";
      this.config.tokenSource = "memhub_shared";
      return;
    }
    if (this.config.oauthAccessToken) {
      this.config.authMode = "oauth_compat";
      this.config.tokenSource = "auth_oauth";
      return;
    }
    throw new SonicApiError("缺少可复用的 MemHub 登录态，也没有旧版 SonicToken。请先执行 memhub auth login 或 testclaw login。");
  }

  async authHeaders() {
    if (this.config.token) {
      return { SonicToken: this.config.token };
    }
    const credential = this.config.sharedMemHubCredential || readSharedMemHubCredential(this.config.memhubCredentials);
    if (credential) {
      this.config.authMode = "memhub";
      this.config.tokenSource = "memhub_shared";
      const headers = {};
      if (credential.authMode === "api_key") {
        headers["X-API-Key"] = credential.token;
      } else {
        headers.Authorization = `Bearer ${credential.token}`;
      }
      if (credential.baseUrl) {
        headers["X-MemHub-Base-URL"] = credential.baseUrl;
      }
      return headers;
    }
    if (this.config.oauthAccessToken) {
      return { Authorization: `Bearer ${this.config.oauthAccessToken}` };
    }
    await this.ensureAuthenticated();
    return this.authHeaders();
  }

  saveRuntimeConfig() {
    const configPayload = this.configStore.load();
    const authPayload = this.authStore.load();
    delete configPayload.oauth_base_url;
    for (const [key, definition] of Object.entries(CONFIG_KEYS)) {
      delete configPayload[key];
      delete configPayload[definition.legacyKey];
      delete authPayload[key];
      delete authPayload[definition.legacyKey];
    }
    const allValues = configToKeyValue(this.config);
    for (const [key, value] of Object.entries(allValues)) {
      if (value === undefined || value === null || value === "") {
        continue;
      }
      const definition = CONFIG_KEYS[key];
      if (definition.scope === "auth") {
        authPayload[key] = value;
      } else {
        configPayload[key] = value;
      }
    }
    this.configStore.save(configPayload);
    this.authStore.save(authPayload);
  }

  clearAuth() {
    const authPayload = this.authStore.load();
    for (const [key, definition] of Object.entries(CONFIG_KEYS)) {
      if (definition.scope !== "auth") {
        continue;
      }
      delete authPayload[key];
      delete authPayload[definition.legacyKey];
      this.config[definition.field] = null;
    }
    this.authStore.save(authPayload);
    const clearedMemHubSession = clearTestClawSessionFromMemHub(this.config.memhubCredentialsPath);
    this.config.authMode = "missing";
    this.config.tokenSource = "missing";
    this.config.user = null;
    return {
      ok: true,
      auth_path: this.config.authPath,
      memhub_credentials_path: this.config.memhubCredentialsPath,
      cleared_legacy_memhub_testclaw_session: clearedMemHubSession,
      shared_memhub_logout: false,
      cleared: Object.keys(CONFIG_KEYS).filter((key) => CONFIG_KEYS[key].scope === "auth"),
    };
  }

  static resolveExecutable(binary) {
    if (!binary) {
      return null;
    }
    if (binary.includes("/") || binary.includes("\\")) {
      return fs.existsSync(binary) ? path.resolve(binary) : null;
    }
    const result = spawnSync("command", ["-v", binary], {
      shell: true,
      encoding: "utf8",
    });
    return result.status === 0 ? result.stdout.trim().split(/\r?\n/)[0] : null;
  }

  async doctor({ version } = {}) {
    const checks = [];
    const pushCheck = (name, ok, detail = {}) => {
      checks.push({ name, ok: Boolean(ok), ...detail });
    };

    pushCheck("config.base_url", Boolean(this.config.baseUrl), {
      value: this.config.baseUrl || null,
      source: process.env.SONIC_BASE_URL ? "env" : "config",
    });
    pushCheck("config.adb_bin", Boolean(this.config.adbBin), {
      value: this.config.adbBin || null,
      resolved_path: SonicBackend.resolveExecutable(this.config.adbBin),
      source: process.env.SONIC_ADB_BIN ? "env" : "config",
    });

    const auth = {
      has_token: Boolean(this.config.token),
      has_memhub_credential: Boolean(readSharedMemHubCredential(this.config.memhubCredentials)),
      has_oauth_access_token: Boolean(this.config.oauthAccessToken),
      has_oauth_refresh_token: Boolean(this.config.oauthRefreshToken),
      oauth_client_id: this.config.oauthClientId || null,
      mode: this.config.authMode,
      token_source: this.config.tokenSource,
      memhub: summarizeSharedMemHubCredentials(this.config.memhubCredentials),
    };
    pushCheck("auth.credential", auth.has_token || auth.has_memhub_credential, { source: auth.token_source });

    let controllerReachable = false;
    let controllerStatus = null;
    let controllerError = null;
    try {
      const response = await this.request("GET", "/users/loginConfig", { auth: false });
      controllerReachable = true;
      controllerStatus = response.code || 2000;
    } catch (error) {
      controllerError = error.message;
    }
    pushCheck("endpoint.controller", controllerReachable, {
      status: controllerStatus,
      error: controllerError,
    });

    let authenticated = false;
    let authenticatedError = null;
    let permissionProbe = false;
    let permissionProbeError = null;
    let authenticatedFallback = null;
    if (auth.has_token || auth.has_memhub_credential) {
      try {
        await this.getCurrentUser();
        authenticated = true;
      } catch (error) {
        const fallback = await this.resolveUserFallback(error);
        if (fallback?.ok) {
          authenticated = true;
          authenticatedFallback = fallback.fallback;
          this.config.user = fallback.user;
          permissionProbe = !fallback.probe_error;
          if (fallback.probe_error) {
            permissionProbeError = fallback.probe_error.message;
          }
        } else {
          authenticatedError = error.message;
          if (fallback?.probe_error) {
            permissionProbeError = fallback.probe_error.message;
          }
        }
      }
      if (authenticated && !permissionProbe) {
        try {
          await this.listProjects();
          permissionProbe = true;
        } catch (error) {
          permissionProbeError = error.message;
        }
      }
    }
    pushCheck("auth.current_user", !(auth.has_token || auth.has_memhub_credential) || authenticated, {
      skipped: !(auth.has_token || auth.has_memhub_credential),
      error: authenticatedError,
      fallback: authenticatedFallback,
    });
    pushCheck("auth.permission_probe", !(auth.has_token || auth.has_memhub_credential) || !authenticated || permissionProbe, {
      skipped: !(auth.has_token || auth.has_memhub_credential) || !authenticated,
      error: permissionProbeError,
    });

    return {
      ok: checks.every((check) => check.ok || check.skipped),
      tool: {
        name: "testclaw",
        version: version || null,
        node: process.version,
      },
      config: {
        base_url: this.config.baseUrl,
        api_prefix: this.config.apiPrefix,
        config_path: this.config.configPath,
        auth_path: this.config.authPath,
        memhub_credentials_path: this.config.memhubCredentialsPath,
        adb_bin: this.config.adbBin,
      },
      auth,
      checks,
      next_steps: checks
        .filter((check) => !check.ok && !check.skipped)
        .map((check) => {
          if (check.name === "config.base_url") {
            return "运行 testclaw config set base_url <url>";
          }
          if (check.name === "auth.credential") {
            return "运行 memhub auth login 或 testclaw login";
          }
          if (check.name === "auth.permission_probe") {
            return "确认当前 MemHub 用户在 TestClaw 中有项目访问权限";
          }
          if (check.name === "endpoint.controller") {
            return "确认 TestClaw 服务可访问，或更新 base_url";
          }
          if (check.name === "config.adb_bin") {
            return "运行 testclaw config set adb_bin <adb路径>";
          }
          return `检查 ${check.name}`;
        }),
    };
  }

  configView(verbose = false) {
    const payload = {
      base_url: this.config.baseUrl,
      adb_bin: this.config.adbBin,
    };
    if (verbose) {
      Object.assign(payload, {
        derived_oauth_base_url: inferOAuthBaseUrl(this.config.baseUrl),
        oauth_access_token: this.config.oauthAccessToken,
        oauth_client_id: this.config.oauthClientId,
        has_token: Boolean(this.config.token),
        has_oauth_refresh_token: Boolean(this.config.oauthRefreshToken),
        auth_mode: this.config.authMode,
        token_source: this.config.tokenSource,
        memhub_credentials_path: this.config.memhubCredentialsPath,
        config_path: this.config.configPath,
        auth_path: this.config.authPath,
      });
    }
    return payload;
  }

  async login(username, password) {
    const response = await this.request("POST", "/users/login", {
      body: { userName: username, password },
      auth: false,
    });
    this.config.token = response.data;
    this.saveRuntimeConfig();
    return response;
  }

  async getCurrentUser() {
    return this.request("GET", "/users");
  }

  isAuthenticationException(error) {
    const message = String(error?.message || "");
    return message.includes("Sonic 业务错误 1001") || message.includes("Authentication Exception");
  }

  getFallbackUserCandidate() {
    const sharedCredential =
      this.config.sharedMemHubCredential || readSharedMemHubCredential(this.config.memhubCredentials);
    if (this.config.user || sharedCredential?.user) {
      return this.config.user || sharedCredential?.user || null;
    }
    const memhubPayload = decodeJwtPayload(this.config.memhubCredentials?.access_token);
    if (!memhubPayload) {
      return null;
    }
    return {
      id: memhubPayload.memhubSub || memhubPayload.sub || null,
      userId: memhubPayload.memhubSub || memhubPayload.sub || null,
      userName: memhubPayload.code || memhubPayload.sub || null,
      username: memhubPayload.code || memhubPayload.sub || null,
      name: memhubPayload.code || memhubPayload.sub || null,
    };
  }

  async resolveUserFallback(error) {
    const authMode = this.config.authMode;
    const tokenSource = this.config.tokenSource;
    if (!["memhub", "oauth_compat"].includes(authMode) && !["memhub_shared", "auth_oauth"].includes(tokenSource)) {
      return null;
    }
    if (!this.isAuthenticationException(error)) {
      return null;
    }

    const user = this.normalizeUser(this.getFallbackUserCandidate());
    if (!user.username && !user.name && !user.email) {
      let probeError = null;
      try {
        await this.listProjects();
      } catch (permissionError) {
        probeError = permissionError;
      }
      return {
        ok: false,
        error,
        probe_error: probeError,
      };
    }

    let probe = null;
    let probeError = null;
    try {
      probe = await this.listProjects();
    } catch (permissionError) {
      probeError = permissionError;
    }

    return {
      ok: true,
      user,
      raw: null,
      roles: [],
      admin: false,
      fallback: "shared_memhub_user",
      probe,
      probe_error: probeError,
      error,
    };
  }

  normalizeUser(rawUser) {
    const user = rawUser?.data || rawUser || {};
    return {
      id: user.id ?? user.userId ?? null,
      username: user.userName || user.username || user.name || null,
      email: user.email || user.mail || null,
      name: user.name || user.nickName || user.userName || user.username || null,
    };
  }

  async whoami() {
    try {
      const raw = await this.getCurrentUser();
      const user = this.normalizeUser(raw);
      this.config.user = user;
      return {
        base_url: this.config.baseUrl,
        auth_mode: this.config.authMode,
        token_source: this.config.tokenSource,
        user,
        roles: raw?.data?.roles || raw?.data?.roleList || [],
        admin: Boolean(raw?.data?.admin || raw?.data?.isAdmin),
        raw,
      };
    } catch (error) {
      const fallback = await this.resolveUserFallback(error);
      if (!fallback?.ok) {
        throw error;
      }
      this.config.user = fallback.user;
      return {
        base_url: this.config.baseUrl,
        auth_mode: this.config.authMode,
        token_source: this.config.tokenSource,
        user: fallback.user,
        roles: fallback.roles,
        admin: fallback.admin,
        raw: fallback.raw,
        fallback: fallback.fallback,
        warning: error.message,
      };
    }
  }

  async completeMemHubLogin(result) {
    this.config.oauthAccessToken = result.access_token;
    this.config.oauthRefreshToken = result.refresh_token || null;
    this.config.oauthClientId = result.client_id;
    this.config.authMode = "memhub";
    this.config.tokenSource = "oauth_compat";
    const whoami = await this.whoami();
    this.config.user = whoami.user;
    this.saveRuntimeConfig();
    return {
      ok: true,
      base_url: this.config.baseUrl,
      auth_mode: this.config.authMode,
      token_source: this.config.tokenSource,
      user: whoami.user,
      memhub_credentials_path: this.config.memhubCredentialsPath,
    };
  }

  async listProjects() {
    return this.request("GET", "/projects/list");
  }

  async listDevices({ page = 1, pageSize = 20, deviceInfo, status = [] } = {}) {
    return this.request("GET", "/devices/list", {
      query: {
        page,
        pageSize,
        deviceInfo,
        "status[]": status,
      },
    });
  }

  async getDevice(deviceId) {
    return this.request("GET", "/devices", { query: { id: deviceId } });
  }

  async findDeviceByUdid(udid) {
    const response = await this.listDevices({ page: 1, pageSize: 100, deviceInfo: udid });
    const records = response.data?.records || [];
    const matches = records.filter((record) => record.udId === udid);
    if (matches.length !== 1) {
      throw new SonicApiError(`udId ${udid} 解析失败，匹配数量为 ${matches.length}。`);
    }
    return matches[0];
  }

  async resolveDevice({ deviceId, udid }) {
    if (deviceId) {
      return (await this.getDevice(deviceId)).data;
    }
    if (udid) {
      return this.findDeviceByUdid(udid);
    }
    throw new SonicApiError("device-id 和 udid 至少要传一个。");
  }

  async runAgentCommand(agentId, { cmd, args = [] } = {}) {
    if (!agentId) {
      throw new SonicApiError("设备缺少 agentId，无法通过 Agent 执行命令。");
    }
    const response = await this.request("POST", `/agents/${agentId}/command`, {
      body: { cmd, args },
    });
    const data = response.data || {};
    if (["error", "timeout"].includes(String(data.status || "").toLowerCase())) {
      throw new SonicApiError(data.error || `Agent 命令执行失败: ${cmd}`);
    }
    return response;
  }

  async runDeviceAdbCommand({ deviceId, udid, args }) {
    const device = await this.resolveDevice({ deviceId, udid });
    if (device.platform !== 1) {
      throw new SonicApiError(`设备 ${device.id} 不是 Android。`);
    }
    const resolvedArgs = typeof args === "function" ? args(device) : args;
    const response = await this.runAgentCommand(device.agentId, { cmd: "adb", args: resolvedArgs });
    return {
      ...response,
      executionMode: "server_agent",
      resolvedDevice: {
        id: device.id,
        udId: device.udId,
        name: device.name,
        status: device.status,
        platform: device.platform,
        agentId: device.agentId,
      },
      adbArgs: resolvedArgs,
    };
  }

  async prepareAndroidDebug({ deviceId, udid, sasRemotePort, uia2RemotePort } = {}) {
    const device = await this.resolveDevice({ deviceId, udid });
    if (device.platform !== 1) {
      throw new SonicApiError(`设备 ${device.id} 不是 Android。`);
    }
    if (device.status !== "ONLINE") {
      throw new SonicApiError(`设备 ${device.id} 当前状态为 ${device.status}，无法占用。`);
    }
    const response = await this.request("POST", "/devices/occupy", {
      body: {
        udId: device.udId,
        sasRemotePort: sasRemotePort || 56000 + Number(device.id),
        uia2RemotePort: uia2RemotePort || 57000 + Number(device.id),
      },
    });
    const adbAddress = extractAdbAddress(response.data?.sas);
    return {
      ...response,
      resolvedDevice: {
        id: device.id,
        udId: device.udId,
        name: device.name,
        status: device.status,
        platform: device.platform,
        agentId: device.agentId,
      },
      adbAddress,
      adbAddressUsage: "compatibility_only",
      executionMode: "server_agent",
      uia2ServerUrl: response.data?.uia2,
      message: "设备已通过 TestClaw Server 占用；后续业务操作默认通过 Server -> Agent 执行，不需要本机 adb connect。",
    };
  }

  async releaseDevice({ deviceId, udid, adbAddress } = {}) {
    if (adbAddress && !deviceId && !udid) {
      throw new SonicApiError("当前 CLI 首版 release 需要 device-id 或 udid，不支持仅靠 adb-address 反查。");
    }
    const device = await this.resolveDevice({ deviceId, udid });
    const response = await this.request("GET", "/devices/release", { query: { udId: device.udId } });
    return {
      ...response,
      resolvedDevice: {
        id: device.id,
        udId: device.udId,
        name: device.name,
        status: device.status,
        platform: device.platform,
        agentId: device.agentId,
      },
    };
  }

  async listInstalledApps({ deviceId, udid } = {}) {
    const result = await this.runDeviceAdbCommand({
      deviceId,
      udid,
      args: (device) => ["-s", device.udId, "shell", "pm", "list", "packages"],
    });
    const stdout = result.data?.stdout || "";
    return {
      ...result,
      packages: stdout
        .split(/\r?\n/)
        .map((line) => line.replace(/^package:/, "").trim())
        .filter(Boolean),
    };
  }

  async installPackage() {
    throw new SonicApiError("app install 已禁用本地 adb 安装。请先使用 package upload，后续将接入 Server -> Agent 安装接口。");
  }

  async openApp({ deviceId, udid, appId } = {}) {
    return this.runDeviceAdbCommand({
      deviceId,
      udid,
      args: (device) => [
        "-s",
        device.udId,
        "shell",
        "monkey",
        "-p",
        appId,
        "-c",
        "android.intent.category.LAUNCHER",
        "1",
      ],
    });
  }

  async killApp({ deviceId, udid, appId } = {}) {
    return this.runDeviceAdbCommand({
      deviceId,
      udid,
      args: (device) => ["-s", device.udId, "shell", "am", "force-stop", appId],
    });
  }

  async uninstallApp({ deviceId, udid, appId } = {}) {
    return this.runDeviceAdbCommand({
      deviceId,
      udid,
      args: (device) => ["-s", device.udId, "uninstall", appId],
    });
  }

  async runSuite(suiteId) {
    return this.request("GET", "/testSuites/runSuite", { query: { id: suiteId } });
  }

  async getResult(resultId) {
    return this.request("GET", "/results", { query: { id: resultId } });
  }

  async rawRequest(method, resourcePath, { query, body, auth = true } = {}) {
    return this.request(method, resourcePath, { query, body, auth });
  }

  async uploadFile(resourcePath, filePath, typeName = "packageFiles", auth = true) {
    const absolutePath = path.resolve(filePath);
    if (!fs.existsSync(absolutePath)) {
      throw new SonicApiError(`文件不存在：${absolutePath}`);
    }
    const form = new FormData();
    form.set("type", typeName);
    form.set("file", new Blob([fs.readFileSync(absolutePath)]), path.basename(absolutePath));
    const headers = {};
    if (auth) {
      Object.assign(headers, await this.authHeaders());
    }
    const response = await fetch(this.buildAbsoluteUrl(resourcePath), {
      method: "POST",
      headers,
      body: form,
    });
    const text = await response.text();
    if (!response.ok) {
      throw new SonicApiError(`HTTP ${response.status}: ${text}`);
    }
    const payload = text ? JSON.parse(text) : {};
    if (payload && typeof payload === "object" && ![undefined, null, 2000].includes(payload.code)) {
      throw new SonicApiError(`Sonic 业务错误 ${payload.code}: ${payload.message || "unknown error"}`);
    }
    return payload;
  }

  static diffById(before = [], after = []) {
    const beforeIds = new Set(before.map((item) => Number(item.id || 0)));
    return after.filter((item) => !beforeIds.has(Number(item.id || 0)));
  }

  static findLatestMatchingRecord(records = [], predicate) {
    return [...records]
      .filter(predicate)
      .sort((left, right) => Number(right.id || 0) - Number(left.id || 0))[0] || null;
  }

  static buildReferenceObjects(ids = [], records = []) {
    const recordMap = new Map(records.filter((item) => item.id !== undefined).map((item) => [Number(item.id), item]));
    const normalizedIds = [];
    ids.forEach((item) => {
      const value = Number(item);
      if (value && !normalizedIds.includes(value)) {
        normalizedIds.push(value);
      }
    });
    return normalizedIds.map((value) => recordMap.get(value) || { id: value });
  }

  async listModules(projectId) {
    return this.request("GET", "/modules/list", { query: { projectId } });
  }

  async getModule(moduleId) {
    return this.request("GET", "/modules", { query: { id: moduleId } });
  }

  async createModule({ projectId, name, moduleId }) {
    const before = moduleId ? null : (await this.listModules(projectId)).data || [];
    const saveResponse = await this.request("PUT", "/modules", {
      body: { id: moduleId, projectId, name },
    });
    let savedEntity;
    if (moduleId) {
      savedEntity = (await this.getModule(moduleId)).data;
    } else {
      const after = (await this.listModules(projectId)).data || [];
      const created = SonicBackend.diffById(before, after);
      const predicate = (item) => item.projectId === projectId && item.name === name;
      savedEntity =
        SonicBackend.findLatestMatchingRecord(created, predicate) ||
        SonicBackend.findLatestMatchingRecord(after, predicate);
    }
    return { ...saveResponse, savedEntity };
  }

  async listAllTestCases(projectId, platform) {
    return this.request("GET", "/testCases/listAll", { query: { projectId, platform } });
  }

  async getTestCase(caseId) {
    return this.request("GET", "/testCases", { query: { id: caseId } });
  }

  async createTestCase({
    projectId,
    platform,
    name,
    moduleId = 0,
    version = "",
    des = "",
    caseId,
    zentaoCaseLinkId,
    zentaoCaseId,
    zentaoCaseTitle,
    zentaoProductId,
  }) {
    const before = caseId ? null : (await this.listAllTestCases(projectId, platform)).data || [];
    const saveResponse = await this.request("PUT", "/testCases", {
      body: {
        id: caseId,
        name,
        platform,
        projectId,
        moduleId: moduleId || 0,
        version: version || "",
        des: des || "",
        zentaoCaseLinkChanged: Boolean(zentaoCaseId || zentaoCaseLinkId),
        zentaoCaseLinkId,
        zentaoCaseId,
        zentaoCaseTitle,
        zentaoProductId,
      },
    });
    let savedEntity;
    if (caseId) {
      savedEntity = (await this.getTestCase(caseId)).data;
    } else {
      const after = (await this.listAllTestCases(projectId, platform)).data || [];
      const created = SonicBackend.diffById(before, after);
      const predicate = (item) => item.projectId === projectId && item.platform === platform && item.name === name;
      savedEntity =
        SonicBackend.findLatestMatchingRecord(created, predicate) ||
        SonicBackend.findLatestMatchingRecord(after, predicate);
    }
    return { ...saveResponse, savedEntity };
  }

  async listSteps(caseId) {
    return this.request("GET", "/steps/listAll", { query: { caseId } });
  }

  async getStep(stepId) {
    return this.request("GET", "/steps", { query: { id: stepId } });
  }

  async getElement(elementId) {
    return (await this.request("GET", "/elements", { query: { id: elementId } })).data;
  }

  async createStep({
    projectId,
    platform,
    stepType,
    caseId,
    publicStepsId,
    parentId = 0,
    content = "",
    text = "",
    error = 3,
    conditionType = 0,
    disabled = 0,
    elementIds = [],
    elements,
    stepId,
  }) {
    const existingCaseId = caseId || null;
    const before = stepId || !existingCaseId ? null : (await this.listSteps(existingCaseId)).data || [];
    const resolvedElements =
      elements ||
      (
        await Promise.all((elementIds || []).map((elementId) => this.getElement(elementId).catch(() => null)))
      ).filter(Boolean);
    const saveResponse = await this.request("PUT", "/steps", {
      body: {
        id: stepId,
        projectId,
        publicStepsId,
        caseId,
        parentId: parentId || 0,
        platform,
        stepType,
        content: content || "",
        text: text || "",
        error: error ?? 3,
        conditionType: conditionType ?? 0,
        disabled: disabled ?? 0,
        elements: resolvedElements,
      },
    });
    let savedEntity = null;
    if (stepId) {
      savedEntity = (await this.getStep(stepId)).data;
    } else if (existingCaseId) {
      const after = (await this.listSteps(existingCaseId)).data || [];
      const created = SonicBackend.diffById(before, after);
      const predicate = (item) =>
        item.caseId === existingCaseId &&
        item.stepType === stepType &&
        String(item.content || "") === String(content || "") &&
        String(item.text || "") === String(text || "");
      savedEntity =
        SonicBackend.findLatestMatchingRecord(created, predicate) ||
        SonicBackend.findLatestMatchingRecord(after, predicate);
    }
    return { ...saveResponse, savedEntity };
  }

  async listAllSuites(projectId) {
    return this.request("GET", "/testSuites/listAll", { query: { projectId } });
  }

  async getSuite(suiteId) {
    return this.request("GET", "/testSuites", { query: { id: suiteId } });
  }

  async createSuite({
    projectId,
    platform,
    name,
    cover,
    isOpenPerfmon,
    perfmonInterval,
    deviceIds = [],
    testCaseIds = [],
    alertRobotIds = null,
    devices,
    testCases,
    suiteId,
  }) {
    const before = suiteId ? null : (await this.listAllSuites(projectId)).data || [];
    const resolvedDevices =
      devices ||
      (await Promise.all(deviceIds.map(async (deviceId) => (await this.getDevice(deviceId)).data))).filter(Boolean);
    const resolvedTestCases =
      testCases ||
      SonicBackend.buildReferenceObjects(testCaseIds, (await this.listAllTestCases(projectId, platform)).data || []);
    const saveResponse = await this.request("PUT", "/testSuites", {
      body: {
        id: suiteId,
        name,
        platform,
        cover,
        projectId,
        isOpenPerfmon: isOpenPerfmon,
        perfmonInterval,
        testCases: resolvedTestCases,
        devices: resolvedDevices,
        alertRobotIds,
      },
    });
    let savedEntity;
    if (suiteId) {
      savedEntity = (await this.getSuite(suiteId)).data;
    } else {
      const after = (await this.listAllSuites(projectId)).data || [];
      const created = SonicBackend.diffById(before, after);
      const predicate = (item) => item.projectId === projectId && item.platform === platform && item.name === name;
      savedEntity =
        SonicBackend.findLatestMatchingRecord(created, predicate) ||
        SonicBackend.findLatestMatchingRecord(after, predicate);
    }
    return { ...saveResponse, savedEntity };
  }

  async createPackage({ projectId, pkgName, platform, branch, url, buildUrl }) {
    return this.request("PUT", "/packages", {
      body: {
        projectId,
        pkgName,
        platform,
        branch,
        url,
        buildUrl: buildUrl || url,
      },
    });
  }

  async uploadPackage({ filePath, projectId, pkgName, platform, branch, buildUrl, typeName = "packageFiles" }) {
    const uploadResponse = await this.uploadFile("/api/folder/upload", filePath, typeName);
    let uploadedUrl = uploadResponse.data;
    if (typeof uploadedUrl === "string" && uploadedUrl.startsWith("/")) {
      uploadedUrl = this.buildAbsoluteUrl(uploadedUrl);
    }
    const packageResponse = await this.createPackage({
      projectId,
      pkgName,
      platform,
      branch,
      url: uploadedUrl,
      buildUrl: buildUrl || uploadedUrl,
    });
    return {
      code: packageResponse.code || 2000,
      message: packageResponse.message || "success",
      data: {
        uploadResponse,
        packageResponse,
        package: {
          projectId,
          pkgName,
          platform,
          branch,
          url: uploadedUrl,
          buildUrl: buildUrl || uploadedUrl,
        },
      },
    };
  }

  async listZentaoProjects({ keyword, limit } = {}) {
    return this.request("GET", "/zentao/projects", { query: { keyword, limit } });
  }

  async searchZentaoProducts({ keyword, limit } = {}) {
    return this.request("GET", "/zentao/products", { query: { keyword, limit } });
  }

  async getZentaoBindings(projectId) {
    return this.request("GET", "/zentao/project-bindings", { query: { projectId } });
  }

  async saveZentaoBinding(payload) {
    return this.request("POST", "/zentao/project-bindings", { body: payload });
  }

  async listZentaoCaseLinks(caseId) {
    return this.request("GET", "/zentao/case-links", { query: { caseId } });
  }

  async getZentaoTestCase(caseId) {
    return this.request("GET", `/zentao/testcases/${caseId}`);
  }

  async saveZentaoCaseLink(payload) {
    return this.request("POST", "/zentao/case-links", { body: payload });
  }

  async deleteZentaoCaseLink(id) {
    return this.request("DELETE", `/zentao/case-links/${id}`);
  }

  async importZentaoCaseSteps(payload) {
    return this.request("POST", "/zentao/case-links/import-steps", { body: payload });
  }

  async listZentaoCaseStepMappings({ caseId, zentaoCaseId } = {}) {
    return this.request("GET", "/zentao/case-step-mappings", { query: { caseId, zentaoCaseId } });
  }

  async saveZentaoCaseStepMappings(payload) {
    return this.request("POST", "/zentao/case-step-mappings", { body: payload });
  }

  async listZentaoCaseResultLinks({ resultId, caseId } = {}) {
    return this.request("GET", "/zentao/case-result-links", { query: { resultId, caseId } });
  }

  async retryZentaoCaseResult(payload) {
    return this.request("POST", "/zentao/case-result-links/retry", { body: payload });
  }

  async listZentaoBugLinks({ resultId, caseId } = {}) {
    return this.request("GET", "/zentao/bug-links", { query: { resultId, caseId } });
  }

  async createZentaoBug(payload) {
    return this.request("POST", "/zentao/bugs", { body: payload });
  }

  async retryZentaoBug(linkId) {
    return this.request("POST", `/zentao/bugs/${linkId}/retry`);
  }

  async generateAiCases(payload) {
    return this.request("POST", "/ai/test-cases/generate", { body: payload });
  }

  async getAiJob(id) {
    return this.request("GET", `/ai/jobs/${id}`);
  }

  async approveAiJob(id, payload = {}) {
    return this.request("POST", `/ai/jobs/${id}/approve`, { body: payload });
  }

  async reportAgentExecution(payload) {
    return this.request("POST", "/agent/executions/report", { body: payload });
  }

  async createSecurityTask(payload) {
    return this.request("POST", "/security/tasks", { body: payload });
  }

  async listSecurityTasks({ projectId } = {}) {
    return this.request("GET", "/security/tasks", { query: { projectId } });
  }

  async ingestSecurityReport(taskId, report) {
    return this.request("POST", `/security/tasks/${taskId}/report`, { body: report });
  }

  async getSecurityReport(taskId) {
    return this.request("GET", `/security/tasks/${taskId}/report`);
  }
}

module.exports = {
  SonicBackend,
  buildConfig,
  extractAdbAddress,
  inferOAuthBaseUrl,
};

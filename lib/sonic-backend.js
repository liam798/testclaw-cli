const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const { CONFIG_KEYS, buildConfig, configToKeyValue } = require("./config");
const { SonicApiError } = require("./errors");

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
      if (!this.config.token) {
        throw new SonicApiError("缺少 SonicToken，请先执行 login。");
      }
      requestHeaders.SonicToken = this.config.token;
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
    return {
      ok: true,
      auth_path: this.config.authPath,
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
      has_oauth_access_token: Boolean(this.config.oauthAccessToken),
      has_oauth_refresh_token: Boolean(this.config.oauthRefreshToken),
      oauth_client_id: this.config.oauthClientId || null,
      token_source: process.env.SONIC_TOKEN ? "env" : (this.config.token ? "auth" : "missing"),
    };
    pushCheck("auth.token", auth.has_token, { source: auth.token_source });

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
    if (this.config.token) {
      try {
        await this.getCurrentUser();
        authenticated = true;
      } catch (error) {
        authenticatedError = error.message;
      }
    }
    pushCheck("auth.current_user", !this.config.token || authenticated, {
      skipped: !this.config.token,
      error: authenticatedError,
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
          if (check.name === "auth.token") {
            return "运行 testclaw login";
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
      },
      adbAddress,
      executionMode: "local",
      localCommands: {
        connectAdb: `adb connect ${adbAddress}`,
        uia2ServerUrl: response.data?.uia2,
      },
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
      },
    };
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
      if (!this.config.token) {
        throw new SonicApiError("缺少 SonicToken，请先执行 login。");
      }
      headers.SonicToken = this.config.token;
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

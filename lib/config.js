const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

function expandHome(inputPath) {
  if (!inputPath) {
    return inputPath;
  }
  if (inputPath === "~") {
    return os.homedir();
  }
  if (inputPath.startsWith("~/")) {
    return path.join(os.homedir(), inputPath.slice(2));
  }
  return inputPath;
}

class JsonStore {
  constructor(configPath) {
    this.path = path.resolve(expandHome(configPath));
  }

  load() {
    if (!fs.existsSync(this.path)) {
      return {};
    }
    return JSON.parse(fs.readFileSync(this.path, "utf8"));
  }

  save(payload) {
    fs.mkdirSync(path.dirname(this.path), { recursive: true });
    fs.writeFileSync(this.path, `${JSON.stringify(payload, null, 2)}\n`, "utf8");
  }
}

const CONFIG_KEYS = {
  base_url: {
    field: "baseUrl",
    legacyKey: "base_url",
    scope: "config",
    defaultValue: "http://127.0.0.1:3001",
    normalize: (value) => value.replace(/\/+$/, ""),
  },
  token: {
    field: "token",
    legacyKey: "token",
    scope: "auth",
    defaultValue: null,
  },
  "oauth.accessToken": {
    field: "oauthAccessToken",
    legacyKey: "oauth_access_token",
    scope: "auth",
    defaultValue: null,
  },
  "oauth.refreshToken": {
    field: "oauthRefreshToken",
    legacyKey: "oauth_refresh_token",
    scope: "auth",
    defaultValue: null,
  },
  "oauth.clientId": {
    field: "oauthClientId",
    legacyKey: "oauth_client_id",
    scope: "auth",
    defaultValue: null,
  },
  adb_bin: {
    field: "adbBin",
    legacyKey: "adb_bin",
    scope: "config",
    defaultValue: "adb",
  },
};

const PUBLIC_CONFIG_KEYS = Object.fromEntries(
  Object.entries(CONFIG_KEYS).filter(([, definition]) => definition.scope === "config"),
);

function normalizeConfigValue(key, value) {
  const definition = CONFIG_KEYS[key];
  if (!definition) {
    throw new Error(`未知配置项: ${key}`);
  }
  const text = String(value);
  return definition.normalize ? definition.normalize(text) : text;
}

function getSavedConfigValue(primarySaved, key) {
  const definition = CONFIG_KEYS[key];
  if (Object.prototype.hasOwnProperty.call(primarySaved, key)) {
    return primarySaved[key];
  }
  if (Object.prototype.hasOwnProperty.call(primarySaved, definition.legacyKey)) {
    return primarySaved[definition.legacyKey];
  }
  return definition.defaultValue;
}

function configToKeyValue(config) {
  return Object.fromEntries(
    Object.entries(CONFIG_KEYS)
      .filter(([, definition]) => config[definition.field])
      .map(([key, definition]) => [key, config[definition.field]]),
  );
}

function configToPublicKeyValue(config) {
  return Object.fromEntries(
    Object.entries(CONFIG_KEYS)
      .filter(([, definition]) => definition.scope === "config")
      .map(([key, definition]) => [key, config[definition.field] ?? ""]),
  );
}

function buildConfig(overrides = {}) {
  const configPath =
    overrides.configPath ||
    process.env.SONIC_CLI_CONFIG ||
    "~/.config/testclaw/config.json";
  const configStore = new JsonStore(configPath);
  const authPath =
    overrides.authPath ||
    process.env.SONIC_CLI_AUTH ||
    path.join(path.dirname(configStore.path), "auth.json");
  const authStore = new JsonStore(authPath);
  const savedConfig = configStore.load();
  const savedAuth = authStore.load();
  const config = {
    baseUrl: (overrides.baseUrl || process.env.SONIC_BASE_URL || getSavedConfigValue(savedConfig, "base_url")).replace(/\/+$/, ""),
    apiPrefix: (process.env.SONIC_API_PREFIX || "/api/controller").replace(/\/+$/, ""),
    token: overrides.token || process.env.SONIC_TOKEN || getSavedConfigValue(savedAuth, "token"),
    oauthAccessToken: process.env.SONIC_OAUTH_ACCESS_TOKEN || getSavedConfigValue(savedAuth, "oauth.accessToken"),
    oauthRefreshToken: process.env.SONIC_OAUTH_REFRESH_TOKEN || getSavedConfigValue(savedAuth, "oauth.refreshToken"),
    oauthClientId: process.env.SONIC_OAUTH_CLIENT_ID || getSavedConfigValue(savedAuth, "oauth.clientId"),
    adbBin: overrides.adbBin || process.env.SONIC_ADB_BIN || getSavedConfigValue(savedConfig, "adb_bin"),
    configPath: configStore.path,
    authPath: authStore.path,
  };
  return { config, configStore, authStore };
}

module.exports = {
  CONFIG_KEYS,
  PUBLIC_CONFIG_KEYS,
  JsonStore,
  buildConfig,
  configToPublicKeyValue,
  configToKeyValue,
  expandHome,
  normalizeConfigValue,
};

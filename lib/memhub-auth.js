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

function defaultMemHubCredentialsPath() {
  return path.join(os.homedir(), ".memhub", "credentials.json");
}

function resolveMemHubCredentialsPath(overrides = {}) {
  return path.resolve(expandHome(
    overrides.memhubCredentialsPath ||
      process.env.TESTCLAW_MEMHUB_CREDENTIALS ||
      process.env.MEMHUB_CREDENTIALS ||
      defaultMemHubCredentialsPath(),
  ));
}

function loadSharedMemHubCredentials(credentialsPath) {
  if (!credentialsPath || !fs.existsSync(credentialsPath)) {
    return {};
  }
  return JSON.parse(fs.readFileSync(credentialsPath, "utf8"));
}

function saveSharedMemHubCredentials(credentialsPath, payload) {
  fs.mkdirSync(path.dirname(credentialsPath), { recursive: true });
  fs.writeFileSync(credentialsPath, `${JSON.stringify(payload, null, 2)}\n`, {
    encoding: "utf8",
    mode: 0o600,
  });
  try {
    fs.chmodSync(credentialsPath, 0o600);
  } catch {
    // Best effort on platforms/filesystems that do not support chmod.
  }
}

function normalizeBaseUrl(baseUrl) {
  return String(baseUrl || "").replace(/\/+$/, "");
}

function readSharedMemHubCredential(sharedCredentials = {}) {
  const token = sharedCredentials.api_key || sharedCredentials.access_token;
  if (!token) {
    return null;
  }
  return {
    token,
    authMode: sharedCredentials.auth_mode || (sharedCredentials.api_key ? "api_key" : "access_token"),
    baseUrl: normalizeBaseUrl(sharedCredentials.base_url || "https://memhub.vvicat.dev"),
    user: sharedCredentials.user || null,
  };
}

function clearTestClawSessionFromMemHub(credentialsPath) {
  const sharedCredentials = loadSharedMemHubCredentials(credentialsPath);
  if (!sharedCredentials.clients?.testclaw) {
    return false;
  }
  const clients = { ...sharedCredentials.clients };
  delete clients.testclaw;
  const nextCredentials = { ...sharedCredentials };
  if (Object.keys(clients).length) {
    nextCredentials.clients = clients;
  } else {
    delete nextCredentials.clients;
  }
  saveSharedMemHubCredentials(credentialsPath, nextCredentials);
  return true;
}

function summarizeSharedMemHubCredentials(sharedCredentials = {}) {
  return {
    present: Boolean(Object.keys(sharedCredentials).length),
    base_url: sharedCredentials.base_url || null,
    auth_mode: sharedCredentials.auth_mode || null,
    has_access_token: Boolean(sharedCredentials.access_token),
    has_api_key: Boolean(sharedCredentials.api_key),
    has_legacy_testclaw_session: Boolean(sharedCredentials.clients?.testclaw?.sonic_token || sharedCredentials.clients?.testclaw?.token),
  };
}

module.exports = {
  clearTestClawSessionFromMemHub,
  defaultMemHubCredentialsPath,
  expandHome,
  loadSharedMemHubCredentials,
  readSharedMemHubCredential,
  resolveMemHubCredentialsPath,
  summarizeSharedMemHubCredentials,
};

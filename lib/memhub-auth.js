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

function readTestClawSessionFromMemHub(sharedCredentials = {}, baseUrl) {
  const session = sharedCredentials.clients?.testclaw;
  if (!session || typeof session !== "object") {
    return null;
  }
  if (!session.sonic_token && !session.token) {
    return null;
  }
  const targetBaseUrl = normalizeBaseUrl(baseUrl);
  const sessionBaseUrl = normalizeBaseUrl(session.base_url);
  if (targetBaseUrl && sessionBaseUrl && targetBaseUrl !== sessionBaseUrl) {
    return null;
  }
  return {
    token: session.sonic_token || session.token,
    oauthAccessToken: session.oauth_access_token || null,
    oauthRefreshToken: session.oauth_refresh_token || null,
    oauthClientId: session.oauth_client_id || "testclaw-cli",
    authMode: session.auth_mode || "memhub_oidc",
    user: session.user || null,
    baseUrl: sessionBaseUrl || null,
  };
}

function writeTestClawSessionToMemHub(credentialsPath, session) {
  const sharedCredentials = loadSharedMemHubCredentials(credentialsPath);
  const nextCredentials = {
    ...sharedCredentials,
    clients: {
      ...(sharedCredentials.clients || {}),
      testclaw: {
        base_url: normalizeBaseUrl(session.baseUrl),
        auth_mode: session.authMode || "memhub_oidc",
        sonic_token: session.token,
        oauth_access_token: session.oauthAccessToken || undefined,
        oauth_refresh_token: session.oauthRefreshToken || undefined,
        oauth_client_id: session.oauthClientId || "testclaw-cli",
        user: session.user || undefined,
        updated_at: new Date().toISOString(),
      },
    },
  };
  saveSharedMemHubCredentials(credentialsPath, nextCredentials);
  return nextCredentials.clients.testclaw;
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
    has_testclaw_session: Boolean(sharedCredentials.clients?.testclaw?.sonic_token || sharedCredentials.clients?.testclaw?.token),
  };
}

module.exports = {
  clearTestClawSessionFromMemHub,
  defaultMemHubCredentialsPath,
  expandHome,
  loadSharedMemHubCredentials,
  readTestClawSessionFromMemHub,
  resolveMemHubCredentialsPath,
  summarizeSharedMemHubCredentials,
  writeTestClawSessionToMemHub,
};

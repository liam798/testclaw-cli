const crypto = require("node:crypto");
const http = require("node:http");
const { spawn } = require("node:child_process");
const { URL, URLSearchParams } = require("node:url");
const { OAuthLoginError } = require("./errors");

const TESTCLAW_CLI_CLIENT_ID = "testclaw-cli";

function debug(...args) {
  if (process.env.SONIC_CLI_DEBUG_OAUTH === "1") {
    process.stderr.write(`[oauth] ${args.join(" ")}\n`);
  }
}

function base64Url(buffer) {
  return Buffer.from(buffer)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function createPkcePair() {
  const verifier = base64Url(crypto.randomBytes(48));
  const challenge = base64Url(crypto.createHash("sha256").update(verifier).digest());
  return { verifier, challenge };
}

async function readJsonResponse(url, options = {}) {
  const response = await fetch(url, options);
  if (!response.ok && response.status !== 302) {
    throw new OAuthLoginError(`OAuth 请求失败: HTTP ${response.status} ${await response.text()}`);
  }
  const text = await response.text();
  const payload = text ? JSON.parse(text) : {};
  if (payload && typeof payload === "object" && payload.code !== undefined && payload.code !== 2000) {
    throw new OAuthLoginError(`OAuth 业务错误 ${payload.code}: ${payload.message || "unknown error"}`);
  }
  return payload;
}

function inferBrowserOpener() {
  if (process.platform === "darwin") {
    return "open";
  }
  if (process.platform === "win32") {
    return "cmd";
  }
  return "xdg-open";
}

function openAuthorizeUrl(authorizeUrl, browserCommand) {
  return new Promise((resolve, reject) => {
    let command = browserCommand;
    let args = [authorizeUrl];
    if (!command) {
      command = inferBrowserOpener();
      if (process.platform === "win32") {
        args = ["/c", "start", "", authorizeUrl];
      }
    }
    const child = spawn(command, args, {
      stdio: "ignore",
    });
    child.on("error", (error) => {
      reject(new OAuthLoginError(`无法打开浏览器，请手动访问：${authorizeUrl} (${error.message})`));
    });
    child.once("spawn", resolve);
  });
}

async function oauthLogin({
  oauthBaseUrl,
  browserCommand,
  listenHost = "127.0.0.1",
  listenPort = 0,
  timeoutSeconds = 180,
}) {
  const baseUrl = oauthBaseUrl.replace(/\/+$/, "");
  const state = base64Url(crypto.randomBytes(16));
  const { verifier, challenge } = createPkcePair();
  let callbackResult = { code: null, state: null, error: null };
  let resolveCallback;
  const callbackPromise = new Promise((resolve) => {
    resolveCallback = resolve;
  });

  const server = http.createServer((req, res) => {
    debug("callback", req.url);
    const requestUrl = new URL(req.url, `http://${listenHost}`);
    callbackResult = {
      code: requestUrl.searchParams.get("code"),
      state: requestUrl.searchParams.get("state"),
      error: requestUrl.searchParams.get("error"),
    };
    res.writeHead(200, {
      "Content-Type": "text/html; charset=utf-8",
      Connection: "close",
    });
    res.end("<html><body><h1>登录完成</h1><p>可以回到 testclaw 终端。</p></body></html>");
    resolveCallback();
  });

  await new Promise((resolve) => server.listen(listenPort, listenHost, resolve));
  const address = server.address();
  const callbackUrl = `http://${listenHost}:${address.port}/callback`;
  debug("listen", callbackUrl);

  try {
    const clientId = TESTCLAW_CLI_CLIENT_ID;
    const authorizeUrl = new URL(`${baseUrl}/authorize`);
    authorizeUrl.search = new URLSearchParams({
      client_id: clientId,
      redirect_uri: callbackUrl,
      response_type: "code",
      code_challenge: challenge,
      code_challenge_method: "S256",
      scope: "openid profile sonic:session",
      state,
      resource: `${baseUrl}/cli/session`,
    }).toString();
    debug("open", authorizeUrl.toString());

    await openAuthorizeUrl(authorizeUrl.toString(), browserCommand);
    debug("opened");

    let timeoutId;
    try {
      await Promise.race([
        callbackPromise,
        new Promise((_, reject) => {
          timeoutId = setTimeout(() => reject(new OAuthLoginError("等待 OAuth 回调超时。")), timeoutSeconds * 1000);
        }),
      ]);
    } finally {
      if (timeoutId) {
        clearTimeout(timeoutId);
      }
    }

    if (callbackResult.error) {
      throw new OAuthLoginError(`OAuth 回调失败：${callbackResult.error}`);
    }
    if (callbackResult.state !== state) {
      throw new OAuthLoginError("OAuth state 不匹配。");
    }
    if (!callbackResult.code) {
      throw new OAuthLoginError("OAuth 回调缺少授权码。");
    }
    debug("callback-ok", callbackResult.code);

    const tokenResponse = await readJsonResponse(`${baseUrl}/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        client_id: clientId,
        code: callbackResult.code,
        code_verifier: verifier,
        redirect_uri: callbackUrl,
        resource: `${baseUrl}/cli/session`,
      }).toString(),
    });
    debug("token-ok");

    const sessionResponse = await readJsonResponse(`${baseUrl}/cli/session`, {
      headers: { Authorization: `Bearer ${tokenResponse.access_token}` },
    });
    debug("session-ok");

    return {
      client_id: clientId,
      access_token: tokenResponse.access_token,
      refresh_token: tokenResponse.refresh_token,
      session: sessionResponse.data,
      oauth_base_url: baseUrl,
    };
  } finally {
    debug("close");
    server.closeAllConnections?.();
    await new Promise((resolve) => server.close(resolve));
  }
}

module.exports = {
  TESTCLAW_CLI_CLIENT_ID,
  createPkcePair,
  oauthLogin,
};

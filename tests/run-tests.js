const assert = require("node:assert/strict");
const fs = require("node:fs");
const http = require("node:http");
const os = require("node:os");
const path = require("node:path");
const { spawn } = require("node:child_process");
const { normalizeAdbAddress } = require("../lib/adb-backend");
const { buildConfig, JsonStore } = require("../lib/config");
const { CommandSession } = require("../lib/session");
const { extractAdbAddress, inferOAuthBaseUrl, SonicBackend } = require("../lib/sonic-backend");

const CLI = path.resolve(__dirname, "../bin/testclaw.js");

function runCli(args, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [CLI, ...args], {
      env: { ...process.env, ...(options.env || {}) },
      stdio: ["pipe", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => {
      stdout += chunk.toString("utf8");
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk.toString("utf8");
    });
    child.on("error", reject);
    child.on("close", (code, signal) => {
      resolve({ code, signal, stdout, stderr });
    });
    child.stdin.end(options.input || "");
  });
}

function logPass(name) {
  process.stdout.write(`✔ ${name}\n`);
}

async function runCoreChecks() {
  assert.equal(normalizeAdbAddress("adb connect 127.0.0.1:5555"), "127.0.0.1:5555");
  assert.equal(normalizeAdbAddress("http://127.0.0.1:5555/path"), "127.0.0.1:5555");
  logPass("normalizeAdbAddress works");

  const payload = "debug ready\nadb connect 192.168.1.11:56001\nuia2 http://127.0.0.1:57001/wd/hub";
  assert.equal(extractAdbAddress(payload), "192.168.1.11:56001");
  logPass("extractAdbAddress works");

  assert.equal(
    inferOAuthBaseUrl("http://127.0.0.1:3001", "/api/controller"),
    "http://127.0.0.1:3001/api/oauth",
  );
  assert.equal(inferOAuthBaseUrl("http://127.0.0.1:3001/", ""), "http://127.0.0.1:3001/api/oauth");
  logPass("inferOAuthBaseUrl works");

  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "testclaw-core-"));
  const configPath = path.join(tempRoot, "config.json");
  fs.writeFileSync(configPath, JSON.stringify({ token: "from-config-should-ignore" }), "utf8");
  fs.writeFileSync(path.join(tempRoot, "auth.json"), JSON.stringify({ token: "from-auth" }), "utf8");
  const { config, configStore, authStore } = buildConfig({
    baseUrl: "http://127.0.0.1:3001",
    apiPrefix: "/api/controller",
    configPath,
  });
  assert.equal(config.token, "from-auth");
  config.oauthAccessToken = "oauth-access";
  config.oauthRefreshToken = "oauth-refresh";
  config.oauthClientId = "oauth-client";
  const backend = new SonicBackend(config, new JsonStore(configStore.path), new JsonStore(authStore.path));
  assert.deepEqual(backend.configView(), {
    base_url: "http://127.0.0.1:3001",
    adb_bin: "adb",
  });
  const verbose = backend.configView(true);
  assert.equal(verbose.derived_oauth_base_url, "http://127.0.0.1:3001/api/oauth");
  assert.equal(verbose.oauth_access_token, "oauth-access");
  assert.equal(verbose.oauth_client_id, "oauth-client");
  assert.equal(verbose.has_token, true);
  assert.equal(verbose.has_oauth_refresh_token, true);
  fs.rmSync(tempRoot, { recursive: true, force: true });
  logPass("buildConfig and configView behave as expected");

  const initRoot = fs.mkdtempSync(path.join(os.tmpdir(), "testclaw-init-"));
  const skillSource = path.join(initRoot, "testclaw-skills");
  fs.mkdirSync(path.join(skillSource, "testclaw-cli", "references"), { recursive: true });
  fs.writeFileSync(path.join(skillSource, "testclaw-cli", "SKILL.md"), "# TestClaw CLI Skill\n", "utf8");
  fs.writeFileSync(path.join(skillSource, "testclaw-cli", "references", "tools.md"), "tools\n", "utf8");
  fs.mkdirSync(path.join(initRoot, ".codex"), { recursive: true });
  fs.mkdirSync(path.join(initRoot, ".claude"), { recursive: true });
  const initResult = await runCli(["--json", "init", "--source-dir", skillSource], {
    env: { HOME: initRoot, USERPROFILE: initRoot },
  });
  assert.equal(initResult.code, 0, initResult.stderr);
  const initPayload = JSON.parse(initResult.stdout);
  assert.equal(initPayload.ok, true);
  assert.equal(initPayload.skill, "testclaw-cli");
  assert.ok(fs.existsSync(path.join(initRoot, ".codex", "skills", "testclaw-cli", "SKILL.md")));
  assert.ok(fs.existsSync(path.join(initRoot, ".claude", "skills", "testclaw-cli", "SKILL.md")));
  assert.ok(fs.existsSync(path.join(initRoot, ".agents", "skills", "testclaw-cli", "SKILL.md")));
  fs.rmSync(initRoot, { recursive: true, force: true });
  logPass("init installs testclaw-cli skill into detected and fallback directories");

  const updateCheck = await runCli(["--json", "update", "--check", "--spec", "file:."], {
    env: { ...process.env },
  });
  assert.equal(updateCheck.code, 0, updateCheck.stderr);
  const updatePayload = JSON.parse(updateCheck.stdout);
  assert.equal(updatePayload.ok, true);
  assert.equal(updatePayload.package, "testclaw");
  assert.equal(updatePayload.currentVersion, updatePayload.latestVersion);
  logPass("update --check reports installable version");

  class FakeBackend {
    async releaseDevice({ udid }) {
      return { released: true, udId: udid };
    }

    async prepareAndroidDebug({ deviceId, udid }) {
      return {
        adbAddress: "127.0.0.1:56001",
        resolvedDevice: { id: deviceId || 1, udId: udid || "device-1" },
      };
    }

    killApp(adbAddress, appId) {
      return { killed: true, adbAddress, appId };
    }

    openApp({ deviceId, udid, appId }) {
      return { opened: true, deviceId, udid, appId };
    }
  }
  const session = new CommandSession();
  const app = { backend: new FakeBackend() };
  session.rememberPrepare(
    { deviceId: 1, udId: "device-1" },
    { adbAddress: "127.0.0.1:56001", resolvedDevice: { id: 1, udId: "device-1" } },
  );
  assert.equal((await session.undo(app)).ok, true);
  assert.equal((await session.redo(app)).ok, true);
  logPass("session undo and redo for prepare");
}

function createFakeAdb(tempRoot) {
  const adbPath = path.join(tempRoot, "adb");
  fs.writeFileSync(
    adbPath,
    `#!/bin/sh
set -eu
if [ "$1" = "connect" ]; then
  echo "connected to $2"
  exit 0
fi
if [ "$1" = "-s" ] && [ "$3" = "shell" ] && [ "$4" = "monkey" ]; then
  echo "Events injected: 1"
  exit 0
fi
if [ "$1" = "-s" ] && [ "$3" = "shell" ] && [ "$4" = "am" ]; then
  exit 0
fi
if [ "$1" = "-s" ] && [ "$3" = "install" ]; then
  echo "Success"
  exit 0
fi
if [ "$1" = "-s" ] && [ "$3" = "uninstall" ]; then
  echo "Success"
  exit 0
fi
if [ "$1" = "-s" ] && [ "$3" = "shell" ] && [ "$4" = "logcat" ]; then
  echo "I ActivityManager: displayed test app"
  exit 0
fi
if [ "$1" = "-s" ] && [ "$3" = "shell" ] && [ "$4" = "dumpsys" ]; then
  echo "Window #1 com.demo/.MainActivity"
  exit 0
fi
if [ "$1" = "-s" ] && [ "$3" = "shell" ] && [ "$4" = "screencap" ]; then
  echo "screenshot ok"
  exit 0
fi
echo "unexpected args: $*" >&2
exit 1
`,
    "utf8",
  );
  fs.chmodSync(adbPath, 0o755);
  return adbPath;
}

function createFakeBrowser(tempRoot) {
  const browserPath = path.join(tempRoot, "fake-browser.js");
  fs.writeFileSync(
    browserPath,
    `#!/usr/bin/env node
const authorizeUrl = new URL(process.argv[2]);
const payload = new URLSearchParams(authorizeUrl.searchParams);
payload.set("username", "liam");
payload.set("password", "secret");
const authorizeEndpoint = new URL(authorizeUrl.toString());
authorizeEndpoint.pathname = authorizeEndpoint.pathname.replace(/\\/[^/]+$/, "/authorize");
authorizeEndpoint.search = "";
(async () => {
  const authorizeResponse = await fetch(authorizeEndpoint, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: payload.toString(),
    redirect: "manual",
  });
  const callbackUrl = authorizeResponse.headers.get("location");
  if (!callbackUrl) {
    throw new Error("missing callback location");
  }
  await fetch(callbackUrl);
})().catch((error) => {
  console.error(error.stack || String(error));
  process.exit(1);
});
`,
    "utf8",
  );
  fs.chmodSync(browserPath, 0o755);
  return browserPath;
}

function createExecutable(tempRoot, name, body) {
  const filePath = path.join(tempRoot, name);
  fs.writeFileSync(filePath, body, "utf8");
  fs.chmodSync(filePath, 0o755);
  return filePath;
}

function jsonResponse(res, payload) {
  const body = JSON.stringify(payload);
  res.writeHead(200, {
    "Content-Type": "application/json",
    "Content-Length": Buffer.byteLength(body),
    Connection: "close",
  });
  res.end(body);
}

async function runE2EChecks() {
  let modules = [];
  let testCases = [];
  let steps = [];
  let suites = [];
  let packages = [];
  let zentaoBindings = [];
  let zentaoCaseLinks = [];
  let zentaoCaseStepMappings = [];
  let zentaoCaseResultLinks = [];
  let zentaoBugLinks = [];
  let agentReports = [];
  let securityTasks = [];
  let securityReports = new Map();
  let agentCommandCalls = [];
  let securityTaskId = 600;
  let moduleId = 100;
  let caseId = 200;
  let stepId = 300;
  let suiteId = 400;
  const server = http.createServer((req, res) => {
    const requestUrl = new URL(req.url, "http://127.0.0.1");
    const readBody = async () => {
      const chunks = [];
      for await (const chunk of req) {
        chunks.push(chunk);
      }
      return Buffer.concat(chunks).toString("utf8");
    };

    (async () => {
      if (req.method === "POST" && requestUrl.pathname === "/api/controller/users/login") {
        jsonResponse(res, { code: 2000, message: "ok", data: "token-123" });
        return;
      }
      if (req.method === "GET" && requestUrl.pathname === "/api/controller/users/loginConfig") {
        jsonResponse(res, { code: 2000, message: "ok", data: { normalEnable: true } });
        return;
      }
      if (req.method === "GET" && requestUrl.pathname === "/api/controller/users") {
        jsonResponse(res, { code: 2000, message: "ok", data: { userName: "liam" } });
        return;
      }
      if (req.method === "GET" && requestUrl.pathname === "/api/controller/devices") {
        jsonResponse(res, { code: 2000, message: "ok", data: { id: 1, udId: "device-1", platform: 1, status: "ONLINE", name: "Pixel 4", agentId: 7 } });
        return;
      }
      if (req.method === "GET" && requestUrl.pathname === "/api/controller/devices/list") {
        jsonResponse(res, {
          code: 2000,
          message: "ok",
          data: { records: [{ id: 1, udId: "device-1", platform: 1, status: "ONLINE", name: "Pixel 4", agentId: 7 }] },
        });
        return;
      }
      if (req.method === "POST" && requestUrl.pathname === "/api/controller/devices/occupy") {
        jsonResponse(res, {
          code: 2000,
          message: "ok",
          data: { sas: "adb connect 127.0.0.1:56001", uia2: "http://127.0.0.1:57001/wd/hub" },
        });
        return;
      }
      if (req.method === "GET" && requestUrl.pathname === "/api/controller/devices/release") {
        jsonResponse(res, { code: 2000, message: "released", data: true });
        return;
      }
      if (req.method === "POST" && requestUrl.pathname === "/api/controller/agents/7/command") {
        const payload = JSON.parse((await readBody()) || "{}");
        agentCommandCalls.push(payload);
        assert.equal(payload.cmd, "adb");
        if (payload.args.join(" ") === "-s device-1 shell pm list packages") {
          jsonResponse(res, { code: 2000, message: "success", data: { status: "success", stdout: "package:com.demo.app\n" } });
          return;
        }
        if (payload.args.join(" ") === "-s device-1 shell monkey -p com.demo.app -c android.intent.category.LAUNCHER 1") {
          jsonResponse(res, { code: 2000, message: "success", data: { status: "success", stdout: "Events injected: 1" } });
          return;
        }
        if (payload.args.join(" ") === "-s device-1 shell am force-stop com.demo.app") {
          jsonResponse(res, { code: 2000, message: "success", data: { status: "success", stdout: "" } });
          return;
        }
        if (payload.args.join(" ") === "-s device-1 uninstall com.demo.app") {
          jsonResponse(res, { code: 2000, message: "success", data: { status: "success", stdout: "Success" } });
          return;
        }
        jsonResponse(res, { code: 2000, message: "success", data: { status: "error", error: `unexpected args: ${payload.args.join(" ")}` } });
        return;
      }
      if (req.method === "POST" && requestUrl.pathname === "/api/oauth/authorize") {
        const body = await readBody();
        const params = new URLSearchParams(body);
        assert.equal(params.get("client_id"), "testclaw-cli");
        const location = `${params.get("redirect_uri")}?code=oauth-code-1&state=${params.get("state")}`;
        res.writeHead(302, { Location: location, Connection: "close" });
        res.end();
        return;
      }
      if (req.method === "POST" && requestUrl.pathname === "/api/oauth/token") {
        const body = await readBody();
        const params = new URLSearchParams(body);
        assert.equal(params.get("client_id"), "testclaw-cli");
        jsonResponse(res, {
          access_token: "oauth-access-1",
          refresh_token: "oauth-refresh-1",
          token_type: "bearer",
          expires_in: 3600,
          scope: "openid profile sonic:session",
        });
        return;
      }
      if (req.method === "GET" && requestUrl.pathname === "/api/oauth/cli/session") {
        assert.equal(req.headers.authorization, "Bearer oauth-access-1");
        jsonResponse(res, {
          code: 2000,
          message: "success",
          data: { subject: "liam", userName: "liam", sonicToken: "token-123" },
        });
        return;
      }
      if (req.method === "GET" && requestUrl.pathname === "/api/controller/modules/list") {
        jsonResponse(res, { code: 2000, message: "success", data: modules });
        return;
      }
      if (req.method === "PUT" && requestUrl.pathname === "/api/controller/modules") {
        const payload = JSON.parse((await readBody()) || "{}");
        moduleId += 1;
        modules.unshift({ ...payload, id: payload.id || moduleId });
        jsonResponse(res, { code: 2000, message: "success" });
        return;
      }
      if (req.method === "GET" && requestUrl.pathname === "/api/controller/testCases/listAll") {
        jsonResponse(res, { code: 2000, message: "success", data: testCases });
        return;
      }
      if (req.method === "PUT" && requestUrl.pathname === "/api/controller/testCases") {
        const payload = JSON.parse((await readBody()) || "{}");
        caseId += 1;
        testCases.unshift({ ...payload, id: payload.id || caseId });
        jsonResponse(res, { code: 2000, message: "success" });
        return;
      }
      if (req.method === "GET" && requestUrl.pathname === "/api/controller/steps/listAll") {
        const currentCaseId = Number(requestUrl.searchParams.get("caseId"));
        jsonResponse(res, { code: 2000, message: "success", data: steps.filter((item) => item.caseId === currentCaseId) });
        return;
      }
      if (req.method === "GET" && requestUrl.pathname === "/api/controller/elements") {
        jsonResponse(res, { code: 2000, message: "success", data: { id: 301, eleName: "登录按钮", eleType: "id", eleValue: "login_btn" } });
        return;
      }
      if (req.method === "PUT" && requestUrl.pathname === "/api/controller/steps") {
        const payload = JSON.parse((await readBody()) || "{}");
        stepId += 1;
        steps.push({ ...payload, id: payload.id || stepId });
        jsonResponse(res, { code: 2000, message: "success" });
        return;
      }
      if (req.method === "GET" && requestUrl.pathname === "/api/controller/testSuites/listAll") {
        jsonResponse(res, { code: 2000, message: "success", data: suites });
        return;
      }
      if (req.method === "PUT" && requestUrl.pathname === "/api/controller/testSuites") {
        const payload = JSON.parse((await readBody()) || "{}");
        suiteId += 1;
        suites.unshift({ ...payload, id: payload.id || suiteId });
        jsonResponse(res, { code: 2000, message: "success" });
        return;
      }
      if (req.method === "POST" && requestUrl.pathname === "/api/folder/upload") {
        await readBody();
        jsonResponse(res, { code: 2000, message: "upload.ok", data: "/packageFiles/demo.apk" });
        return;
      }
      if (req.method === "PUT" && requestUrl.pathname === "/api/controller/packages") {
        const payload = JSON.parse((await readBody()) || "{}");
        packages.push(payload);
        jsonResponse(res, { code: 2000, message: "update.ok" });
        return;
      }
      if (req.method === "GET" && requestUrl.pathname === "/api/controller/zentao/projects") {
        jsonResponse(res, { code: 2000, message: "success", data: { projects: [{ id: 17, name: "Sonic Video" }] } });
        return;
      }
      if (req.method === "GET" && requestUrl.pathname === "/api/controller/zentao/products") {
        jsonResponse(res, { code: 2000, message: "success", data: { products: [{ id: 3, name: "咔咔秀" }] } });
        return;
      }
      if (req.method === "GET" && requestUrl.pathname === "/api/controller/zentao/testcases/180") {
        jsonResponse(res, {
          code: 2000,
          message: "success",
          data: {
            testcase: {
              zentaoCaseId: 180,
              zentaoCaseTitle: "登录成功",
              steps: [
                { id: "1", index: 1, step: "输入账号密码", expect: "进入首页" },
                { id: "2", index: 2, step: "查看登录状态", expect: "显示用户名" },
              ],
            },
          },
        });
        return;
      }
      if (req.method === "GET" && requestUrl.pathname === "/api/controller/zentao/project-bindings") {
        const projectId = Number(requestUrl.searchParams.get("projectId"));
        jsonResponse(res, { code: 2000, message: "success", data: zentaoBindings.filter((item) => item.projectId === projectId) });
        return;
      }
      if (req.method === "POST" && requestUrl.pathname === "/api/controller/zentao/project-bindings") {
        const payload = JSON.parse((await readBody()) || "{}");
        zentaoBindings = [{ ...payload, id: payload.id || 1 }];
        jsonResponse(res, { code: 2000, message: "success", data: zentaoBindings[0] });
        return;
      }
      if (req.method === "GET" && requestUrl.pathname === "/api/controller/zentao/case-links") {
        const currentCaseId = Number(requestUrl.searchParams.get("caseId"));
        jsonResponse(res, { code: 2000, message: "success", data: zentaoCaseLinks.filter((item) => item.caseId === currentCaseId) });
        return;
      }
      if (req.method === "POST" && requestUrl.pathname === "/api/controller/zentao/case-links") {
        const payload = JSON.parse((await readBody()) || "{}");
        zentaoCaseLinks.push({ ...payload, id: zentaoCaseLinks.length + 1 });
        jsonResponse(res, { code: 2000, message: "success", data: zentaoCaseLinks[zentaoCaseLinks.length - 1] });
        return;
      }
      if (req.method === "DELETE" && requestUrl.pathname.startsWith("/api/controller/zentao/case-links/")) {
        const linkId = Number(requestUrl.pathname.split("/").pop());
        zentaoCaseLinks = zentaoCaseLinks.filter((item) => item.id !== linkId);
        jsonResponse(res, { code: 2000, message: "delete.ok" });
        return;
      }
      if (req.method === "POST" && requestUrl.pathname === "/api/controller/zentao/case-links/import-steps") {
        const payload = JSON.parse((await readBody()) || "{}");
        assert.equal(payload.projectId, 9);
        assert.equal(payload.caseId, 201);
        assert.equal(payload.zentaoCaseId, 180);
        assert.equal(payload.platform, 1);
        jsonResponse(res, {
          code: 2000,
          message: "success",
          data: { zentaoCaseId: payload.zentaoCaseId, draft: true, imported: 2, mapped: 2 },
        });
        return;
      }
      if (req.method === "GET" && requestUrl.pathname === "/api/controller/zentao/case-step-mappings") {
        const currentCaseId = Number(requestUrl.searchParams.get("caseId"));
        const currentZentaoCaseId = Number(requestUrl.searchParams.get("zentaoCaseId"));
        jsonResponse(res, {
          code: 2000,
          message: "success",
          data: zentaoCaseStepMappings.filter((item) =>
            item.caseId === currentCaseId && (!currentZentaoCaseId || item.zentaoCaseId === currentZentaoCaseId)),
        });
        return;
      }
      if (req.method === "POST" && requestUrl.pathname === "/api/controller/zentao/case-step-mappings") {
        const payload = JSON.parse((await readBody()) || "{}");
        zentaoCaseStepMappings = (payload.mappings || []).map((item, index) => ({
          ...item,
          id: index + 1,
          projectId: payload.projectId,
          caseId: payload.caseId,
          zentaoCaseId: payload.zentaoCaseId,
        }));
        jsonResponse(res, { code: 2000, message: "success", data: zentaoCaseStepMappings });
        return;
      }
      if (req.method === "GET" && requestUrl.pathname === "/api/controller/zentao/case-result-links") {
        const currentCaseId = Number(requestUrl.searchParams.get("caseId"));
        const currentResultId = Number(requestUrl.searchParams.get("resultId"));
        jsonResponse(res, {
          code: 2000,
          message: "success",
          data: zentaoCaseResultLinks.filter((item) =>
            (!currentCaseId || item.caseId === currentCaseId) && (!currentResultId || item.resultId === currentResultId)),
        });
        return;
      }
      if (req.method === "POST" && requestUrl.pathname === "/api/controller/zentao/case-result-links/retry") {
        const payload = JSON.parse((await readBody()) || "{}");
        const link = {
          id: 1,
          resultDetailId: payload.resultDetailId,
          resultId: 501,
          caseId: 201,
          zentaoCaseId: 180,
          status: "submitted",
        };
        zentaoCaseResultLinks = [link];
        jsonResponse(res, { code: 2000, message: "success", data: link });
        return;
      }
      if (req.method === "GET" && requestUrl.pathname === "/api/controller/zentao/bug-links") {
        jsonResponse(res, { code: 2000, message: "success", data: zentaoBugLinks });
        return;
      }
      if (req.method === "POST" && requestUrl.pathname === "/api/controller/zentao/webhook") {
        const payload = JSON.parse((await readBody()) || "{}");
        const objectType = String(payload.objectType || "*").toLowerCase();
        const action = String(payload.action || "*").toLowerCase();
        const eventKey = `${objectType}.${action}`;
        let bugLinksUpdated = 0;
        let caseLinksMarkedChanged = 0;
        if (objectType === "bug" && action === "resolved") {
          for (const link of zentaoBugLinks) {
            if (Number(link.zentaoBugId) === Number(payload.objectID)) {
              link.status = "resolved";
              bugLinksUpdated += 1;
            }
          }
        }
        if ((objectType === "case" || objectType === "testcase") && ["changed", "edited", "updated"].includes(action)) {
          for (const link of zentaoCaseLinks) {
            if (Number(link.zentaoCaseId) === Number(payload.objectID)) {
              link.syncStatus = "changed";
              caseLinksMarkedChanged += 1;
            }
          }
        }
        jsonResponse(res, {
          code: 2000,
          message: "success",
          data: { eventKey, bugLinksUpdated, caseLinksMarkedChanged, robotNotified: true, dispatched: 1 },
        });
        return;
      }
      if (req.method === "POST" && requestUrl.pathname === "/api/controller/zentao/bugs") {
        const payload = JSON.parse((await readBody()) || "{}");
        const duplicate = payload.failureSignature
          ? zentaoBugLinks.find((item) => item.failureSignature === payload.failureSignature)
          : null;
        if (duplicate) {
          jsonResponse(res, { code: 2000, message: "success", data: duplicate });
          return;
        }
        zentaoBugLinks.push({ ...payload, id: zentaoBugLinks.length + 1, zentaoBugId: 9001, status: "submitted" });
        jsonResponse(res, { code: 2000, message: "success", data: zentaoBugLinks[zentaoBugLinks.length - 1] });
        return;
      }
      if (req.method === "POST" && requestUrl.pathname.startsWith("/api/controller/zentao/bugs/") && requestUrl.pathname.endsWith("/retry")) {
        const parts = requestUrl.pathname.split("/");
        const linkId = Number(parts[parts.length - 2]);
        const link = zentaoBugLinks.find((item) => item.id === linkId) || { id: linkId, status: "submitted" };
        const previousError = link.lastError || "";
        link.status = "submitted";
        link.previousError = previousError;
        link.lastError = "";
        jsonResponse(res, { code: 2000, message: "success", data: link });
        return;
      }
      if (req.method === "POST" && requestUrl.pathname === "/api/controller/ai/test-cases/generate") {
        const payload = JSON.parse((await readBody()) || "{}");
        assert.equal(payload.projectId, 9);
        jsonResponse(res, {
          code: 2000,
          message: "success",
          data: {
            id: 77,
            status: "success",
            generatedJson: JSON.stringify({ testCases: [{ title: "登录成功", priority: "P1", type: "functional" }] }),
          },
        });
        return;
      }
      if (req.method === "GET" && requestUrl.pathname === "/api/controller/ai/jobs/77") {
        jsonResponse(res, { code: 2000, message: "success", data: { id: 77, status: "success" } });
        return;
      }
      if (req.method === "POST" && requestUrl.pathname === "/api/controller/ai/jobs/77/approve") {
        jsonResponse(res, { code: 2000, message: "success", data: { createdCases: [{ caseId: 201 }] } });
        return;
      }
      if (req.method === "POST" && requestUrl.pathname === "/api/controller/agent/executions/report") {
        const payload = JSON.parse((await readBody()) || "{}");
        agentReports.push(payload);
        jsonResponse(res, { code: 2000, message: "success", data: { resultDetail: { id: 1 }, zentaoBug: { id: 1 } } });
        return;
      }
      if (req.method === "POST" && requestUrl.pathname === "/api/controller/security/tasks") {
        const payload = JSON.parse((await readBody()) || "{}");
        securityTaskId += 1;
        const task = {
          id: securityTaskId,
          projectId: payload.projectId,
          sampleSha256: payload.sampleSha256,
          packageName: payload.packageName,
          profile: payload.profile,
          status: "QUEUED",
        };
        securityTasks.unshift(task);
        jsonResponse(res, { code: 2000, message: "success", data: task });
        return;
      }
      if (req.method === "GET" && requestUrl.pathname === "/api/controller/security/tasks") {
        jsonResponse(res, { code: 2000, message: "success", data: securityTasks });
        return;
      }
      if (req.method === "POST" && requestUrl.pathname.match(/^\/api\/controller\/security\/tasks\/\d+\/report$/)) {
        const taskId = Number(requestUrl.pathname.split("/").at(-2));
        const payload = JSON.parse((await readBody()) || "{}");
        securityReports.set(taskId, payload);
        const task = securityTasks.find((item) => item.id === taskId);
        if (task) {
          task.status = "COMPLETED";
          task.riskScore = payload.risk?.score;
          task.riskLevel = payload.risk?.level;
        }
        jsonResponse(res, { code: 2000, message: "success", data: { taskId, status: "COMPLETED" } });
        return;
      }
      if (req.method === "GET" && requestUrl.pathname.match(/^\/api\/controller\/security\/tasks\/\d+\/report$/)) {
        const taskId = Number(requestUrl.pathname.split("/").at(-2));
        jsonResponse(res, { code: 2000, message: "success", data: securityReports.get(taskId) || null });
        return;
      }
      res.writeHead(404, { Connection: "close" });
      res.end();
    })().catch((error) => {
      res.writeHead(500, { Connection: "close" });
      res.end(error.stack);
    });
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  const baseUrl = `http://127.0.0.1:${address.port}`;
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "testclaw-e2e-"));
  const configPath = path.join(tempRoot, "config.json");
  const adbPath = createFakeAdb(tempRoot);
  const browserPath = createFakeBrowser(tempRoot);
  const apkPath = path.join(tempRoot, "demo.apk");
  fs.writeFileSync(apkPath, "demo", "utf8");

  try {
    let result = await runCli(["--json", "config", "set", "base_url", `${baseUrl}/`], {
      env: { SONIC_CLI_CONFIG: configPath },
    });
    assert.equal(result.code, 0, result.stderr);
    assert.equal(result.stdout.trim(), "");

    result = await runCli(["--json", "config", "get", "base_url"], {
      env: { SONIC_CLI_CONFIG: configPath },
    });
    assert.equal(result.code, 0, result.stderr);
    assert.equal(JSON.parse(result.stdout), baseUrl);

    result = await runCli(["--json", "config", "set", "adb_bin", adbPath], {
      env: { SONIC_CLI_CONFIG: configPath },
    });
    assert.equal(result.code, 0, result.stderr);
    assert.equal(result.stdout.trim(), "");
    const savedConfig = JSON.parse(fs.readFileSync(configPath, "utf8"));
    assert.equal(savedConfig["base_url"], baseUrl);
    assert.equal(savedConfig["adb_bin"], adbPath);
    assert.equal(savedConfig["base.url"], undefined);
    assert.equal(savedConfig.token, undefined);
    assert.equal(savedConfig["oauth.accessToken"], undefined);
    const authPath = path.join(tempRoot, "auth.json");
    const savedAuth = JSON.parse(fs.readFileSync(authPath, "utf8"));
    assert.equal(savedAuth.token, undefined);

    result = await runCli(["--json", "config", "list"], {
      env: { SONIC_CLI_CONFIG: configPath },
    });
    assert.equal(result.code, 0, result.stderr);
    assert.equal(JSON.parse(result.stdout)["base_url"], baseUrl);
    assert.equal(JSON.parse(result.stdout)["adb_bin"], adbPath);

    result = await runCli(["--json", "config", "unset", "adb_bin"], {
      env: { SONIC_CLI_CONFIG: configPath },
    });
    assert.equal(result.code, 0, result.stderr);
    assert.equal(JSON.parse(result.stdout)["base_url"], baseUrl);
    assert.equal(JSON.parse(result.stdout)["adb_bin"], "adb");

    result = await runCli(["--json", "config", "set", "adb_bin", adbPath], {
      env: { SONIC_CLI_CONFIG: configPath },
    });
    assert.equal(result.code, 0, result.stderr);

    result = await runCli(["--json", "doctor"], {
      env: { SONIC_CLI_CONFIG: configPath },
    });
    assert.equal(result.code, 0, result.stderr);
    const doctorBeforeLogin = JSON.parse(result.stdout);
    assert.equal(doctorBeforeLogin.tool.name, "testclaw");
    assert.equal(doctorBeforeLogin.config.base_url, baseUrl);
    assert.equal(doctorBeforeLogin.auth.has_token, false);
    assert.equal(doctorBeforeLogin.checks.find((check) => check.name === "endpoint.controller").ok, true);

    const loginStartedAt = Date.now();
    result = await runCli(["login", "--browser-command", browserPath, "--timeout-seconds", "5"], {
      env: { SONIC_CLI_CONFIG: configPath },
    });
    assert.equal(result.code, 0, result.stderr);
    assert.ok(Date.now() - loginStartedAt < 4000, "login should exit after successful callback without waiting for timeout");

    result = await runCli(["--json", "doctor"], {
      env: { SONIC_CLI_CONFIG: configPath },
    });
    assert.equal(result.code, 0, result.stderr);
    const doctorAfterLogin = JSON.parse(result.stdout);
    assert.equal(doctorAfterLogin.auth.has_token, true);
    assert.equal(doctorAfterLogin.checks.find((check) => check.name === "auth.current_user").ok, true);

    result = await runCli(["--json", "whoami"], {
      env: { SONIC_CLI_CONFIG: configPath },
    });
    assert.equal(result.code, 0, result.stderr);
    assert.equal(JSON.parse(result.stdout).data.userName, "liam");

    result = await runCli(["--json", "device", "prepare-android-debug", "--device-id", "1"], {
      env: { SONIC_CLI_CONFIG: configPath },
    });
    assert.equal(result.code, 0, result.stderr);
    assert.equal(JSON.parse(result.stdout).adbAddress, "127.0.0.1:56001");

    result = await runCli(["--json", "app", "list-installed", "--device-id", "1"], {
      env: { SONIC_CLI_CONFIG: configPath },
    });
    assert.equal(result.code, 0, result.stderr);
    assert.deepEqual(JSON.parse(result.stdout).packages, ["com.demo.app"]);

    result = await runCli(["--json", "app", "open", "--device-id", "1", "--app-id", "com.demo.app"], {
      env: { SONIC_CLI_CONFIG: configPath },
    });
    assert.equal(result.code, 0, result.stderr);
    assert.equal(JSON.parse(result.stdout).executionMode, "server_agent");
    assert.ok(agentCommandCalls.some((call) => call.args.join(" ") === "-s device-1 shell monkey -p com.demo.app -c android.intent.category.LAUNCHER 1"));

    result = await runCli(["--json", "module", "create", "--project-id", "9", "--name", "登录模块"], {
      env: { SONIC_CLI_CONFIG: configPath },
    });
    assert.equal(result.code, 0, result.stderr);
    assert.equal(JSON.parse(result.stdout).savedEntity.name, "登录模块");

    result = await runCli([
      "--json",
      "case",
      "create",
      "--project-id",
      "9",
      "--platform",
      "1",
      "--name",
      "登录成功用例",
      "--module-id",
      "101",
      "--version",
      "v1.0.0",
      "--des",
      "验证登录成功流程",
      "--zentao-case-id",
      "180",
      "--zentao-case-title",
      "登录成功",
      "--zentao-product-id",
      "3",
    ], {
      env: { SONIC_CLI_CONFIG: configPath },
    });
    assert.equal(result.code, 0, result.stderr);
    assert.equal(testCases[0].zentaoCaseLinkChanged, true);
    assert.equal(testCases[0].zentaoCaseId, 180);
    assert.equal(testCases[0].zentaoCaseTitle, "登录成功");
    assert.equal(testCases[0].zentaoProductId, 3);

    result = await runCli([
      "--json",
      "step",
      "create",
      "--project-id",
      "9",
      "--platform",
      "1",
      "--case-id",
      "201",
      "--step-type",
      "click",
      "--element-id",
      "301",
    ], {
      env: { SONIC_CLI_CONFIG: configPath },
    });
    assert.equal(result.code, 0, result.stderr);

    result = await runCli([
      "--json",
      "suite",
      "create",
      "--project-id",
      "9",
      "--platform",
      "1",
      "--name",
      "登录回归套件",
      "--cover",
      "1",
      "--is-open-perfmon",
      "0",
      "--perfmon-interval",
      "1000",
      "--device-id",
      "1",
      "--test-case-id",
      "201",
    ], {
      env: { SONIC_CLI_CONFIG: configPath },
    });
    assert.equal(result.code, 0, result.stderr);

    result = await runCli([
      "--json",
      "package",
      "upload",
      "--file",
      apkPath,
      "--project-id",
      "9",
      "--pkg-name",
      "demo.apk",
      "--platform",
      "android",
      "--branch",
      "main",
    ], {
      env: { SONIC_CLI_CONFIG: configPath },
    });
    assert.equal(result.code, 0, result.stderr);
    assert.equal(packages.length, 1);

    result = await runCli(["--json", "zentao", "project", "list", "--keyword", "Sonic"], {
      env: { SONIC_CLI_CONFIG: configPath },
    });
    assert.equal(result.code, 0, result.stderr);
    assert.equal(JSON.parse(result.stdout).data.projects[0].id, 17);

    result = await runCli(["--json", "zentao", "product", "search", "--keyword", "咔咔"], {
      env: { SONIC_CLI_CONFIG: configPath },
    });
    assert.equal(result.code, 0, result.stderr);
    assert.equal(JSON.parse(result.stdout).data.products[0].id, 3);

    result = await runCli(["--json", "zentao", "case", "get", "--zentao-case-id", "180"], {
      env: { SONIC_CLI_CONFIG: configPath },
    });
    assert.equal(result.code, 0, result.stderr);
    assert.equal(JSON.parse(result.stdout).data.testcase.zentaoCaseId, 180);
    assert.equal(JSON.parse(result.stdout).data.testcase.steps.length, 2);

    result = await runCli([
      "--json",
      "zentao",
      "binding",
      "set",
      "--project-id",
      "9",
      "--zentao-project-id",
      "17",
      "--zentao-product-id",
      "3",
      "--auto-submit-bug",
      "--zentao-warn-result",
      "blocked",
    ], {
      env: { SONIC_CLI_CONFIG: configPath },
    });
    assert.equal(result.code, 0, result.stderr);
    assert.equal(zentaoBindings[0].zentaoProductId, 3);
    assert.equal(zentaoBindings[0].autoSubmitBug, true);
    assert.equal(zentaoBindings[0].zentaoWarnResult, "blocked");

    result = await runCli(["--json", "zentao", "binding", "get", "--project-id", "9"], {
      env: { SONIC_CLI_CONFIG: configPath },
    });
    assert.equal(result.code, 0, result.stderr);
    assert.equal(JSON.parse(result.stdout).data.length, 1);

    result = await runCli([
      "--json",
      "zentao",
      "case",
      "link",
      "--project-id",
      "9",
      "--case-id",
      "201",
      "--zentao-case-id",
      "180",
      "--zentao-case-title",
      "登录成功",
      "--zentao-product-id",
      "3",
    ], {
      env: { SONIC_CLI_CONFIG: configPath },
    });
    assert.equal(result.code, 0, result.stderr);
    assert.equal(zentaoCaseLinks[0].zentaoCaseId, 180);
    assert.equal(zentaoCaseLinks[0].zentaoCaseTitle, "登录成功");
    assert.equal(zentaoCaseLinks[0].zentaoProductId, 3);

    result = await runCli([
      "--json",
      "zentao",
      "case",
      "import-steps",
      "--project-id",
      "9",
      "--case-id",
      "201",
      "--zentao-case-id",
      "180",
      "--platform",
      "1",
    ], {
      env: { SONIC_CLI_CONFIG: configPath },
    });
    assert.equal(result.code, 0, result.stderr);
    assert.equal(JSON.parse(result.stdout).data.draft, true);
    assert.equal(JSON.parse(result.stdout).data.imported, 2);

    result = await runCli([
      "--json",
      "zentao",
      "step-mapping",
      "set",
      "--project-id",
      "9",
      "--case-id",
      "201",
      "--zentao-case-id",
      "180",
      "--mappings-json",
      JSON.stringify([{ zentaoStepId: "1", zentaoStepIndex: 1, stepIds: "301,302" }]),
    ], {
      env: { SONIC_CLI_CONFIG: configPath },
    });
    assert.equal(result.code, 0, result.stderr);
    assert.equal(zentaoCaseStepMappings[0].zentaoStepIndex, 1);
    assert.equal(zentaoCaseStepMappings[0].stepIds, "301,302");

    result = await runCli(["--json", "zentao", "step-mapping", "list", "--case-id", "201", "--zentao-case-id", "180"], {
      env: { SONIC_CLI_CONFIG: configPath },
    });
    assert.equal(result.code, 0, result.stderr);
    assert.equal(JSON.parse(result.stdout).data.length, 1);

    result = await runCli(["--json", "zentao", "result", "retry", "--result-detail-id", "1001"], {
      env: { SONIC_CLI_CONFIG: configPath },
    });
    assert.equal(result.code, 0, result.stderr);
    assert.equal(JSON.parse(result.stdout).data.status, "submitted");

    result = await runCli(["--json", "zentao", "result", "list", "--case-id", "201"], {
      env: { SONIC_CLI_CONFIG: configPath },
    });
    assert.equal(result.code, 0, result.stderr);
    assert.equal(JSON.parse(result.stdout).data[0].zentaoCaseId, 180);

    result = await runCli(["--json", "zentao", "case", "list", "--case-id", "201"], {
      env: { SONIC_CLI_CONFIG: configPath },
    });
    assert.equal(result.code, 0, result.stderr);
    assert.equal(JSON.parse(result.stdout).data.length, 1);

    result = await runCli([
      "--json",
      "zentao",
      "bug",
      "create",
      "--zentao-product-id",
      "3",
      "--case-id",
      "201",
      "--title",
      "登录失败",
      "--steps",
      "点击登录后无响应",
      "--failure-signature",
      "cli-login-failure",
    ], {
      env: { SONIC_CLI_CONFIG: configPath },
    });
    assert.equal(result.code, 0, result.stderr);
    assert.equal(JSON.parse(result.stdout).data.zentaoBugId, 9001);

    result = await runCli([
      "--json",
      "zentao",
      "bug",
      "create",
      "--zentao-product-id",
      "3",
      "--case-id",
      "201",
      "--title",
      "登录失败",
      "--steps",
      "点击登录后无响应",
      "--failure-signature",
      "cli-login-failure",
    ], {
      env: { SONIC_CLI_CONFIG: configPath },
    });
    assert.equal(result.code, 0, result.stderr);
    assert.equal(JSON.parse(result.stdout).data.id, 1);
    assert.equal(zentaoBugLinks.length, 1);

    result = await runCli(["--json", "zentao", "bug", "list", "--case-id", "201"], {
      env: { SONIC_CLI_CONFIG: configPath },
    });
    assert.equal(result.code, 0, result.stderr);
    const listedBugLinks = JSON.parse(result.stdout).data;
    assert.equal(listedBugLinks[0].status, "submitted");
    assert.equal(listedBugLinks[0].zentaoBugId, 9001);

    zentaoBugLinks[0].status = "failed";
    zentaoBugLinks[0].lastError = "ZenTao API timeout";
    result = await runCli(["--json", "zentao", "bug", "retry", "--link-id", "1"], {
      env: { SONIC_CLI_CONFIG: configPath },
    });
    assert.equal(result.code, 0, result.stderr);
    const retryData = JSON.parse(result.stdout).data;
    assert.equal(retryData.status, "submitted");
    assert.equal(retryData.previousError, "ZenTao API timeout");

    result = await runCli([
      "--json",
      "raw",
      "request",
      "--method",
      "POST",
      "--path",
      "/zentao/webhook",
      "--no-auth",
      "--body",
      JSON.stringify({ objectType: "bug", action: "resolved", objectID: 9001, product: 3 }),
    ], {
      env: { SONIC_CLI_CONFIG: configPath },
    });
    assert.equal(result.code, 0, result.stderr);
    assert.equal(JSON.parse(result.stdout).data.eventKey, "bug.resolved");
    assert.equal(JSON.parse(result.stdout).data.bugLinksUpdated, 1);
    assert.equal(zentaoBugLinks[0].status, "resolved");

    result = await runCli([
      "--json",
      "raw",
      "request",
      "--method",
      "POST",
      "--path",
      "/zentao/webhook",
      "--no-auth",
      "--body",
      JSON.stringify({ objectType: "testcase", action: "changed", objectID: 180, product: 3 }),
    ], {
      env: { SONIC_CLI_CONFIG: configPath },
    });
    assert.equal(result.code, 0, result.stderr);
    assert.equal(JSON.parse(result.stdout).data.eventKey, "testcase.changed");
    assert.equal(JSON.parse(result.stdout).data.caseLinksMarkedChanged, 1);
    assert.equal(zentaoCaseLinks[0].syncStatus, "changed");

    const reqPath = path.join(tempRoot, "requirement.md");
    fs.writeFileSync(reqPath, "登录需求", "utf8");
    result = await runCli(["--json", "ai", "case-generate", "--project-id", "9", "--file", reqPath], {
      env: { SONIC_CLI_CONFIG: configPath },
    });
    assert.equal(result.code, 0, result.stderr);
    assert.equal(JSON.parse(result.stdout).data.id, 77);

    result = await runCli(["--json", "ai", "job", "get", "--id", "77"], {
      env: { SONIC_CLI_CONFIG: configPath },
    });
    assert.equal(result.code, 0, result.stderr);
    assert.equal(JSON.parse(result.stdout).data.status, "success");

    result = await runCli(["--json", "ai", "job", "approve", "--id", "77", "--version", "v1"], {
      env: { SONIC_CLI_CONFIG: configPath },
    });
    assert.equal(result.code, 0, result.stderr);
    assert.equal(JSON.parse(result.stdout).data.createdCases[0].caseId, 201);

    const logPath = path.join(tempRoot, "failure.log");
    fs.writeFileSync(logPath, "button not responding", "utf8");
    result = await runCli([
      "--json",
      "agent",
      "report",
      "--project-id",
      "9",
      "--case-id",
      "201",
      "--step-id",
      "301",
      "--device-id",
      "1",
      "--status",
      "failed",
      "--summary",
      "登录失败",
      "--log-file",
      logPath,
    ], {
      env: { SONIC_CLI_CONFIG: configPath },
    });
    assert.equal(result.code, 0, result.stderr);
    assert.equal(agentReports[0].status, "failed");
    assert.equal(agentReports[0].stepId, 301);

    result = await runCli(["--json", "logout"], {
      env: { SONIC_CLI_CONFIG: configPath },
    });
    assert.equal(result.code, 0, result.stderr);
    assert.equal(JSON.parse(result.stdout).ok, true);
    assert.equal(JSON.parse(fs.readFileSync(authPath, "utf8")).token, undefined);

    result = await runCli(["login", "--username", "admin", "--password", "secret"], {
      env: { SONIC_CLI_CONFIG: configPath },
    });
    assert.equal(result.code, 0, result.stderr);

    result = await runCli([
      "--json",
      "security",
      "task",
      "create",
      "--project-id",
      "9",
      "--sample-sha256",
      "a".repeat(64),
      "--package-name",
      "com.demo",
      "--profile",
      "adware-deep",
    ], {
      env: { SONIC_CLI_CONFIG: configPath },
    });
    assert.equal(result.code, 0, result.stderr);
    const createdSecurityTask = JSON.parse(result.stdout).data;
    assert.equal(createdSecurityTask.status, "QUEUED");

    const securityReportPath = path.join(tempRoot, "security-report.json");
    fs.writeFileSync(securityReportPath, JSON.stringify({ risk: { score: 90, level: "malicious_high_confidence" }, findings: [], iocs: {} }), "utf8");
    result = await runCli([
      "--json",
      "security",
      "task",
      "ingest-report",
      "--task-id",
      String(createdSecurityTask.id),
      "--report",
      securityReportPath,
    ], {
      env: { SONIC_CLI_CONFIG: configPath },
    });
    assert.equal(result.code, 0, result.stderr);
    assert.equal(JSON.parse(result.stdout).data.status, "COMPLETED");

    result = await runCli(["--json", "security", "task", "report", "--task-id", String(createdSecurityTask.id)], {
      env: { SONIC_CLI_CONFIG: configPath },
    });
    assert.equal(result.code, 0, result.stderr);
    assert.equal(JSON.parse(result.stdout).data.risk.score, 90);
  } finally {
    server.closeAllConnections?.();
    await new Promise((resolve) => server.close(resolve));
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }

  logPass("full e2e workflow passes");
}

async function runSecurityAnalysisChecks() {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "testclaw-security-"));
  const apkPath = path.join(tempRoot, "suspicious.apk");
  const outDir = path.join(tempRoot, "artifacts");
  const fakeYara = createExecutable(tempRoot, "fake-yara", `#!/bin/sh\necho "AdDisplay_Generic $2"\n`);
  const fakeQuark = createExecutable(tempRoot, "fake-quark", `#!/bin/sh\necho "Confidence Score: 100% hidden overlay behavior"\n`);
  const fakeLlm = createExecutable(tempRoot, "fake-llm", `#!/usr/bin/env node\nlet input='';process.stdin.on('data',c=>input+=c);process.stdin.on('end',()=>{const payload=JSON.parse(input);console.log(JSON.stringify({summary:'reviewed '+payload.sample.fileName, manual_review:[]}));});\n`);
  const fakeAdb = createFakeAdb(tempRoot);
  const dexArtifact = path.join(tempRoot, "classes-dump.dex");
  const pcapArtifact = path.join(tempRoot, "traffic.pcap");
  fs.writeFileSync(dexArtifact, "dex\n035\0runtime dump", "utf8");
  fs.writeFileSync(pcapArtifact, "pcap demo traffic", "utf8");
  fs.writeFileSync(
    apkPath,
    [
      "package:com.google.android.system.helper",
      "android.permission.SYSTEM_ALERT_WINDOW",
      "android.permission.RECEIVE_BOOT_COMPLETED",
      "android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS",
      "dalvik.system.DexClassLoader",
      "WindowManager.addView",
      "setComponentEnabledSetting",
      "ActivityManager.TaskDescription",
      "generic goldfish qemu frida",
      "https://ads.bad.example/config.json",
      "c2.bad.example",
      "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=",
    ].join("\n"),
    "utf8",
  );

  try {
    let result = await runCli([
      "--json",
      "security",
      "analyze",
      "--file",
      apkPath,
      "--out-dir",
      outDir,
      "--yara-bin",
      fakeYara,
      "--yara-rules",
      path.join(tempRoot, "rules.yar"),
      "--quark-bin",
      fakeQuark,
      "--quark-rules",
      path.join(tempRoot, "quark-rules"),
      "--llm-command",
      fakeLlm,
      "--frida-dex-artifact",
      dexArtifact,
      "--mitm-pcap-path",
      pcapArtifact,
      "--adb-address",
      "127.0.0.1:56001",
      "--package-name",
      "com.demo",
    ], {
      env: { SONIC_ADB_BIN: fakeAdb },
    });
    assert.equal(result.code, 0, result.stderr);
    const analysis = JSON.parse(result.stdout);
    assert.equal(analysis.ok, true);
    assert.equal(analysis.sample.fileName, "suspicious.apk");
    assert.match(analysis.sample.sha256, /^[a-f0-9]{64}$/);
    assert.equal(analysis.risk.level, "malicious_high_confidence");
    assert.ok(analysis.risk.score >= 90);
    assert.ok(analysis.findings.some((finding) => finding.id === "dangerous_permission_overlay"));
    assert.ok(analysis.findings.some((finding) => finding.id === "dynamic_dex_loading"));
    assert.ok(analysis.iocs.urls.includes("https://ads.bad.example/config.json"));
    assert.ok(analysis.iocs.domains.includes("c2.bad.example"));
    assert.ok(analysis.iocs.encryptedStringCandidates.base64.includes("QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo="));
    assert.ok(fs.existsSync(analysis.artifacts.reportPath));
    assert.ok(fs.existsSync(analysis.artifacts.llmReviewPath));
    assert.ok(fs.existsSync(analysis.artifacts.manifestPath));
    assert.ok(fs.existsSync(analysis.artifacts.timelinePath));
    assert.ok(fs.existsSync(analysis.artifacts.stringCandidatesPath));
    assert.ok(fs.existsSync(analysis.artifacts.ruleSuggestionsPath));
    assert.ok(fs.existsSync(analysis.artifacts.htmlReportPath));
    assert.ok(analysis.pipeline.stages.some((stage) => stage.id === "sample_registration" && stage.status === "completed"));
    assert.ok(analysis.pipeline.stages.some((stage) => stage.id === "static_triage" && stage.status === "completed"));
    assert.ok(analysis.pipeline.stages.some((stage) => stage.id === "llm_review" && stage.status === "completed"));
    assert.equal(analysis.evidenceTimeline[0].type, "sample_registered");
    assert.ok(analysis.ruleSuggestions.yara.some((rule) => rule.id === "network_ioc_candidate"));
    assert.ok(analysis.stringDecryption.candidates.base64.length >= 1);
    assert.equal(analysis.pluginStatuses.yara.status, "completed");
    assert.equal(analysis.pluginStatuses.yara.hitCount, 1);
    assert.equal(analysis.pluginStatuses.quark.status, "completed");
    assert.equal(analysis.pluginStatuses.dynamicExecution.status, "completed");
    assert.equal(analysis.pluginStatuses.fridaDex.status, "completed");
    assert.equal(analysis.pluginStatuses.mitmPcap.status, "completed");
    assert.equal(analysis.pluginStatuses.llm.status, "completed");
    for (const engineName of ["mobsf", "yara", "quark", "dynamicExecution", "fridaDex", "mitmPcap", "llm"]) {
      const engine = analysis.pluginStatuses[engineName];
      assert.equal(engine.engine, engineName);
      assert.equal(typeof engine.enabled, "boolean");
      assert.equal(typeof engine.timeoutMs, "number");
      assert.equal(typeof engine.remediationHint, "string");
      assert.ok(engine.remediationHint.length > 0);
    }
    assert.ok(analysis.findings.some((finding) => finding.id === "yara_rule_hit"));
    assert.ok(analysis.findings.some((finding) => finding.id === "quark_behavior_chain_hit"));
    assert.ok(analysis.findings.some((finding) => finding.id === "dynamic_execution_completed"));
    assert.ok(analysis.findings.some((finding) => finding.id === "frida_dex_evidence_collected"));
    assert.ok(analysis.findings.some((finding) => finding.id === "mitm_pcap_evidence_collected"));
    assert.ok(analysis.findings.some((finding) => finding.id === "llm_review_completed"));

    result = await runCli(["--json", "security", "report", "--report", analysis.artifacts.reportPath]);
    assert.equal(result.code, 0, result.stderr);
    const report = JSON.parse(result.stdout);
    assert.equal(report.sample.sha256, analysis.sample.sha256);
    assert.equal(report.risk.level, analysis.risk.level);

    result = await runCli(["--json", "security", "ioc", "--report", analysis.artifacts.reportPath]);
    assert.equal(result.code, 0, result.stderr);
    const ioc = JSON.parse(result.stdout);
    assert.deepEqual(ioc.urls, analysis.iocs.urls);
    assert.deepEqual(ioc.domains, analysis.iocs.domains);

    result = await runCli(["--json", "security", "artifacts", "--report", analysis.artifacts.reportPath]);
    assert.equal(result.code, 0, result.stderr);
    const artifacts = JSON.parse(result.stdout);
    assert.equal(artifacts.sample.sha256, analysis.sample.sha256);
    assert.ok(artifacts.files.some((file) => file.kind === "html_report" && file.exists));
    assert.ok(artifacts.files.some((file) => file.kind === "string_candidates" && file.exists));
    assert.equal(artifacts.engineStatuses.length, 7);
    assert.ok(artifacts.engineStatuses.every((engine) => engine.engine && engine.status && typeof engine.enabled === "boolean"));
    assert.ok(artifacts.engineStatuses.filter((engine) => engine.enabled).every((engine) => engine.artifactPath && engine.artifactExists));

    result = await runCli(["--json", "security", "validate", "--report", analysis.artifacts.reportPath]);
    assert.equal(result.code, 0, result.stderr);
    const validation = JSON.parse(result.stdout);
    assert.equal(validation.ok, true);
    assert.equal(validation.checks.find((check) => check.name === "required_artifacts_exist").ok, true);
    assert.equal(validation.checks.find((check) => check.name === "plugin_statuses_cover_engines").ok, true);
    assert.equal(validation.checks.find((check) => check.name === "enabled_engines_have_artifacts").ok, true);
    assert.equal(validation.checks.find((check) => check.name === "manifest_records_all_engines").ok, true);
    assert.equal(validation.checks.find((check) => check.name === "llm_not_sole_conviction").ok, true);
    logPass("security analysis workflow passes");
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
}

(async () => {
  try {
    await runCoreChecks();
    const help = await runCli(["--help"]);
    assert.equal(help.code, 0, help.stderr);
    assert.match(help.stdout, /testclaw/);
    assert.doesNotMatch(help.stdout, /testclaw-cli|--base-url|--api-prefix|--token|--config-path|--adb-bin/);
    const noArgs = await runCli([]);
    assert.equal(noArgs.code, 0, noArgs.stderr);
    assert.equal(noArgs.stdout, help.stdout);
    assert.doesNotMatch(noArgs.stdout, /testclaw> /);
    const removedGlobal = await runCli(["--base-url", "http://127.0.0.1:3001", "whoami"]);
    assert.notEqual(removedGlobal.code, 0);
    assert.match(removedGlobal.stderr, /未知全局选项/);
    const jsonError = await runCli(["--json", "config", "get", "token"]);
    assert.notEqual(jsonError.code, 0);
    assert.equal(JSON.parse(jsonError.stderr).ok, false);
    logPass("removed global options are rejected");
    await runE2EChecks();
    await runSecurityAnalysisChecks();
  } catch (error) {
    process.stderr.write(`${error.stack || error.message || String(error)}\n`);
    process.exitCode = 1;
  }
})();

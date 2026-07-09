const { spawnSync } = require("node:child_process");
const pkg = require("../package.json");
const { SonicCliError } = require("./errors");

const DEFAULT_INSTALL_SPEC = "git+https://github.com/liam798/testclaw-cli.git";

function runCommand(command, args, options = {}) {
  const result = spawnSync(command, args, {
    encoding: "utf8",
    stdio: options.stdio || "pipe",
    shell: process.platform === "win32",
  });
  return {
    ok: result.status === 0,
    status: result.status,
    signal: result.signal,
    stdout: result.stdout || "",
    stderr: result.stderr || "",
  };
}

function checkTestClawCliUpdate(options = {}) {
  const spec = options.spec || DEFAULT_INSTALL_SPEC;
  const result = runCommand("npm", ["view", spec, "version", "--json"]);
  if (!result.ok) {
    throw new SonicCliError(`检查 testclaw-cli 更新失败：${result.stderr || result.stdout || "unknown error"}`);
  }
  const latestVersion = String(result.stdout || "")
    .trim()
    .replace(/^"|"$/g, "");
  return {
    ok: true,
    package: pkg.name,
    currentVersion: pkg.version,
    latestVersion: latestVersion || null,
    installSpec: spec,
    updateAvailable: Boolean(latestVersion && latestVersion !== pkg.version),
  };
}

function updateTestClawCli(options = {}) {
  const spec = options.spec || DEFAULT_INSTALL_SPEC;
  const before = checkTestClawCliUpdate({ spec });
  if (options.checkOnly) {
    return before;
  }
  const args = ["install", "-g", spec];
  const install = runCommand("npm", args);
  if (!install.ok) {
    throw new SonicCliError(`更新 testclaw-cli 失败：${install.stderr || install.stdout || "unknown error"}`);
  }
  return {
    ...before,
    updated: true,
    command: ["npm", ...args].join(" "),
    message: "testclaw-cli 已更新。请重新执行 testclaw 命令以使用新版本。",
    stdout: options.verbose ? install.stdout : undefined,
    stderr: options.verbose ? install.stderr : undefined,
  };
}

module.exports = {
  DEFAULT_INSTALL_SPEC,
  checkTestClawCliUpdate,
  updateTestClawCli,
};

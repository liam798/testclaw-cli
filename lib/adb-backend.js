const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

function normalizeAdbAddress(adbAddress) {
  return String(adbAddress || "")
    .trim()
    .replace(/^(?:adb\s+connect\s+|ws:\/\/|wss:\/\/|http:\/\/|https:\/\/)/, "")
    .replace(/\/.*$/, "");
}

class LocalAdbBackend {
  constructor(adbBin = "adb", adbEnv = {}) {
    this.adbBin = adbBin;
    this.adbEnv = adbEnv;
  }

  run(args, options = {}) {
    const result = spawnSync(this.adbBin, args, {
      encoding: "utf8",
      env: { ...process.env, ...this.adbEnv },
      timeout: options.timeoutMs || 30000,
      maxBuffer: options.maxBuffer || 1024 * 1024 * 5,
    });
    if (result.status !== 0) {
      throw new Error(
        result.error?.message ||
          result.stderr.trim() ||
          result.stdout.trim() ||
          `adb failed: ${args.join(" ")}`,
      );
    }
    return {
      command: [this.adbBin, ...args].join(" "),
      stdout: result.stdout.trim(),
      stderr: result.stderr.trim(),
    };
  }

  ensureConnection(adbAddress) {
    const normalized = normalizeAdbAddress(adbAddress);
    const connection = this.run(["connect", normalized]);
    return { normalized, connection };
  }

  listInstalledApps(adbAddress) {
    const { normalized, connection } = this.ensureConnection(adbAddress);
    const result = this.run(["-s", normalized, "shell", "pm", "list", "packages"]);
    const packages = result.stdout
      .split(/\r?\n/)
      .map((line) => line.replace(/^package:/, "").trim())
      .filter(Boolean);
    return {
      executionMode: "local",
      adbAddress: normalized,
      packages,
      connection,
      ...result,
    };
  }

  async installPackage(adbAddress, packageUrl) {
    const { normalized, connection } = this.ensureConnection(adbAddress);
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "testclaw-install-"));
    try {
      const fileName = path.basename(new URL(packageUrl).pathname) || "package.apk";
      const targetPath = path.join(tempDir, fileName);
      const response = await fetch(packageUrl);
      if (!response.ok) {
        throw new Error(`下载安装包失败: HTTP ${response.status}`);
      }
      fs.writeFileSync(targetPath, Buffer.from(await response.arrayBuffer()));
      const result = this.run(["-s", normalized, "install", "-r", targetPath]);
      return {
        executionMode: "local",
        adbAddress: normalized,
        packageUrl,
        connection,
        ...result,
      };
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  }

  openApp(adbAddress, appId) {
    const { normalized, connection } = this.ensureConnection(adbAddress);
    const result = this.run([
      "-s",
      normalized,
      "shell",
      "monkey",
      "-p",
      appId,
      "-c",
      "android.intent.category.LAUNCHER",
      "1",
    ]);
    return {
      executionMode: "local",
      adbAddress: normalized,
      appId,
      accepted: true,
      connection,
      ...result,
    };
  }

  killApp(adbAddress, appId) {
    const { normalized, connection } = this.ensureConnection(adbAddress);
    const result = this.run(["-s", normalized, "shell", "am", "force-stop", appId]);
    return {
      executionMode: "local",
      adbAddress: normalized,
      appId,
      accepted: true,
      connection,
      ...result,
    };
  }

  uninstallApp(adbAddress, appId) {
    const { normalized, connection } = this.ensureConnection(adbAddress);
    const result = this.run(["-s", normalized, "uninstall", appId]);
    return {
      executionMode: "local",
      adbAddress: normalized,
      appId,
      connection,
      ...result,
    };
  }
}

module.exports = {
  LocalAdbBackend,
  normalizeAdbAddress,
};

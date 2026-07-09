const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const { SonicCliError } = require("./errors");

const DEFAULT_SKILLS_REPO = "https://github.com/liam798/testclaw-skills.git";
const DEFAULT_SKILLS_REF = "main";

const AGENT_SKILL_TARGETS = [
  { agent: "codex", home: ".codex", skills: ["skills"] },
  { agent: "cursor", home: ".cursor", skills: ["skills"] },
  { agent: "trae", home: ".trae", skills: ["skills"] },
  { agent: "claude-code", home: ".claude", skills: ["skills"] },
  { agent: "gemini", home: ".gemini", skills: ["skills"] },
  { agent: "kiro", home: ".kiro", skills: ["skills"] },
  { agent: "openclaw", home: ".openclaw", skills: ["skills"] },
  { agent: "opencode", home: ".config/opencode", skills: ["skills"] },
  { agent: "windsurf", home: ".codeium/windsurf", skills: ["skills"] },
];

function expandHome(input, homeDir = os.homedir()) {
  if (!input) {
    return input;
  }
  if (input === "~") {
    return homeDir;
  }
  if (input.startsWith("~/")) {
    return path.join(homeDir, input.slice(2));
  }
  return input;
}

function copyDir(sourceDir, targetDir) {
  fs.rmSync(targetDir, { recursive: true, force: true });
  fs.mkdirSync(path.dirname(targetDir), { recursive: true });
  fs.cpSync(sourceDir, targetDir, {
    recursive: true,
    filter: (source) => {
      const base = path.basename(source);
      return base !== ".git" && base !== ".DS_Store" && base !== "node_modules";
    },
  });
}

function resolveSkillSource(sourceDir, homeDir = os.homedir()) {
  if (!sourceDir) {
    return null;
  }
  const resolved = path.resolve(expandHome(sourceDir, homeDir));
  const directSkill = path.join(resolved, "SKILL.md");
  if (fs.existsSync(directSkill)) {
    return resolved;
  }
  const nestedSkill = path.join(resolved, "testclaw-cli", "SKILL.md");
  if (fs.existsSync(nestedSkill)) {
    return path.join(resolved, "testclaw-cli");
  }
  throw new SonicCliError(`未找到 testclaw-cli skill：${resolved}`);
}

function cloneSkillSource({ repo = DEFAULT_SKILLS_REPO, ref = DEFAULT_SKILLS_REF, tempRoot }) {
  const gitCheck = spawnSync("git", ["--version"], { encoding: "utf8" });
  if (gitCheck.status !== 0) {
    throw new SonicCliError("未找到 git，无法自动下载 testclaw-skills。请安装 git 或使用 --source-dir 指定本地 skills 目录。");
  }
  const checkoutDir = fs.mkdtempSync(path.join(tempRoot || os.tmpdir(), "testclaw-skills-"));
  const result = spawnSync("git", ["clone", "--depth", "1", "--branch", ref, repo, checkoutDir], {
    encoding: "utf8",
  });
  if (result.status !== 0) {
    fs.rmSync(checkoutDir, { recursive: true, force: true });
    throw new SonicCliError(`下载 testclaw-skills 失败：${result.stderr || result.stdout || "unknown error"}`);
  }
  return {
    checkoutDir,
    skillDir: path.join(checkoutDir, "testclaw-cli"),
  };
}

function discoverAgentSkillTargets(homeDir = os.homedir()) {
  const targets = [];
  for (const item of AGENT_SKILL_TARGETS) {
    const agentHome = path.join(homeDir, item.home);
    if (!fs.existsSync(agentHome)) {
      continue;
    }
    targets.push({
      agent: item.agent,
      path: path.join(agentHome, ...item.skills),
      detected: true,
    });
  }
  targets.push({
    agent: "fallback",
    path: path.join(homeDir, ".agents", "skills"),
    detected: false,
  });
  return targets;
}

function installTestClawSkills(options = {}) {
  const homeDir = options.homeDir ? path.resolve(expandHome(options.homeDir)) : os.homedir();
  const dryRun = Boolean(options.dryRun);
  const sourceFromOption = options.sourceDir || process.env.TESTCLAW_SKILLS_SOURCE_DIR;
  const cloned = sourceFromOption
    ? null
    : cloneSkillSource({
      repo: options.repo || DEFAULT_SKILLS_REPO,
      ref: options.ref || DEFAULT_SKILLS_REF,
      tempRoot: options.tempRoot,
    });
  const skillSource = sourceFromOption
    ? resolveSkillSource(sourceFromOption, homeDir)
    : cloned.skillDir;
  if (!fs.existsSync(path.join(skillSource, "SKILL.md"))) {
    if (cloned) {
      fs.rmSync(cloned.checkoutDir, { recursive: true, force: true });
    }
    throw new SonicCliError(`下载的 testclaw-skills 缺少 testclaw-cli/SKILL.md：${skillSource}`);
  }

  const detectedTargets = options.target
    ? [{ agent: "custom", path: path.resolve(expandHome(options.target, homeDir)), detected: true }]
    : discoverAgentSkillTargets(homeDir);
  const installations = [];
  try {
    for (const target of detectedTargets) {
      const installPath = path.join(target.path, "testclaw-cli");
      if (!dryRun) {
        copyDir(skillSource, installPath);
      }
      installations.push({
        agent: target.agent,
        detected: target.detected,
        skillsDir: target.path,
        installPath,
        installed: !dryRun,
      });
    }
  } finally {
    if (cloned) {
      fs.rmSync(cloned.checkoutDir, { recursive: true, force: true });
    }
  }

  return {
    ok: true,
    source: sourceFromOption ? path.resolve(expandHome(sourceFromOption, homeDir)) : options.repo || DEFAULT_SKILLS_REPO,
    skill: "testclaw-cli",
    dryRun,
    fallbackUsed: installations.some((item) => item.agent === "fallback"),
    installations,
  };
}

module.exports = {
  AGENT_SKILL_TARGETS,
  DEFAULT_SKILLS_REF,
  DEFAULT_SKILLS_REPO,
  discoverAgentSkillTargets,
  installTestClawSkills,
  resolveSkillSource,
};

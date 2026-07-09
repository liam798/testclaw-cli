#!/usr/bin/env node

const { main } = require("../lib/cli");
const { formatJson } = require("../lib/formatter");

main(process.argv.slice(2)).catch((error) => {
  const message = error && error.message ? error.message : String(error);
  if (process.argv.slice(2).includes("--json")) {
    console.error(formatJson({
      ok: false,
      error: {
        type: error && error.constructor && error.constructor.name ? error.constructor.name : "Error",
        message,
      },
    }));
  } else {
    console.error(message);
  }
  process.exitCode = 1;
});

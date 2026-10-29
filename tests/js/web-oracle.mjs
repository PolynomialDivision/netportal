// The server's side of the formatting cross-checks (format, presence, v2 tests): the Rust
// formatter (netportal_web::render::format) via crates/netportal-web/examples/format_oracle.rs,
// `cargo run -q -p netportal-web --example format_oracle -- <mode>`, or the prebuilt binary in
// NETPORTAL_WEB_JS_ORACLE. The cases go in as JSON on stdin, the answers come back as JSON.

import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";

export const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");

/** The server's answers for `mode` ("format", "presence", "v2"), or null when the oracle
 *  cannot run (no cargo, a build failure): the cross-checks then skip with SKIP. */
export function askServer(mode, input) {
  const stdin = JSON.stringify(input);
  const oracle = process.env.NETPORTAL_WEB_JS_ORACLE;
  try {
    const out = oracle
      ? execFileSync(oracle, [mode], { input: stdin, encoding: "utf8", maxBuffer: 64 << 20 })
      : execFileSync("cargo", ["run", "-q", "-p", "netportal-web", "--example", "format_oracle", "--", mode],
        { cwd: root, input: stdin, encoding: "utf8", maxBuffer: 64 << 20 });
    return JSON.parse(out);
  } catch {
    return null;
  }
}

export const SKIP = "the Rust oracle (cargo run -p netportal-web --example format_oracle) is not available";

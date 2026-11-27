// captureCookie must settle and remove its throwaway profile when the browser dies by signal before CDP connects.
import { it } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync, chmodSync } from "node:fs";
import os from "node:os";
import path from "node:path";

it("captureCookie settles and cleans up after a browser killed by signal", { skip: process.platform === "win32" }, async () => {
  const tmp = mkdtempSync(path.join(os.tmpdir(), "olm-browser-"));
  const fake = path.join(tmp, "chrome");
  // Writes a dead DevTools port (atomically) into its --user-data-dir, records the dir, then SIGKILLs itself.
  writeFileSync(fake, `#!/bin/sh
for a; do case $a in --user-data-dir=*) p=\${a#*=};; esac; done
echo "$p" > '${tmp}/prof'; printf '1\\n/x\\n' > "$p/port.tmp"; mv "$p/port.tmp" "$p/DevToolsActivePort"
kill -KILL $$
`);
  chmodSync(fake, 0o755);
  process.env.OL_BROWSER = fake;
  delete process.env.OL_SESSION_FD;
  const { captureCookie } = await import("../../src/auth/browserLogin.js");
  let timer: NodeJS.Timeout | undefined;
  const outcome = await Promise.race([
    captureCookie("https://www.overleaf.com", { timeoutMs: 1000 }).then(() => "resolved", () => "rejected"),
    new Promise((r) => { timer = setTimeout(() => r("pending"), 15_000); }),
  ]);
  clearTimeout(timer);
  assert.equal(outcome, "rejected");
  const profile = readFileSync(path.join(tmp, "prof"), "utf8").trim();
  assert.ok(profile.length > 0);
  assert.equal(existsSync(profile), false, `profile left on disk: ${profile}`);
  rmSync(tmp, { recursive: true, force: true });
});

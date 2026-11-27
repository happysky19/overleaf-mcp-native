// Keychain cookie store against a stub `security` on PATH and a temp HOME: never the real Keychain or store.
import { describe, it, before, beforeEach, after } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync, chmodSync } from "node:fs";
import os from "node:os";
import path from "node:path";

const tmp = mkdtempSync(path.join(os.tmpdir(), "olm-keychain-"));
const bin = path.join(tmp, "bin");
const kc = path.join(tmp, "kc"); // stub keychain: kc/item holds the stored secret, kc/mode the stub's behaviour
mkdirSync(bin); mkdirSync(kc);
writeFileSync(path.join(bin, "security"), `#!/bin/sh
K='${kc}'; mode=$(cat "$K/mode" 2>/dev/null)
case "$1" in
  -i) read -r line; [ "$mode" = nosave ] && exit 0; printf %s "\${line##* -X }" | xxd -r -p > "$K/item"; exit 0;;
  find-generic-password|delete-generic-password)
    [ "$mode" = denied ] && { echo "security: User interaction is not allowed." >&2; exit 51; }
    [ -f "$K/item" ] || { echo "security: The specified item could not be found in the keychain." >&2; exit 44; }
    if [ "$1" = find-generic-password ]; then cat "$K/item"; else rm "$K/item"; fi; exit 0;;
esac
exit 1
`);
chmodSync(path.join(bin, "security"), 0o755);
process.env.HOME = tmp;
process.env.PATH = `${bin}:${process.env.PATH}`;
process.env.OL_KEYCHAIN_SERVICE = "overleaf-mcp-unit-test";
delete process.env.OL_SESSION_FD;

const origin = "https://www.overleaf.com";
const legacyDir = path.join(tmp, "Library", "Application Support", "overleaf-mcp");
const legacyFile = path.join(legacyDir, "cookie.json");
const legacyProfile = path.join(legacyDir, "chrome-profile");
const item = path.join(kc, "item");

function seedLegacy(): void {
  mkdirSync(path.join(legacyProfile, "Default"), { recursive: true });
  writeFileSync(path.join(legacyProfile, "Default", "Cookies"), "sqlite");
  writeFileSync(legacyFile, JSON.stringify({ hosts: { "www.overleaf.com": { cookie: "overleaf_session2=legacy", savedAt: 123 } } }));
}

type Store = typeof import("../../src/auth/cookieStore.js");
let store: Store;

describe("Keychain cookie store (darwin)", { skip: process.platform !== "darwin" }, () => {
  before(async () => { store = await import("../../src/auth/cookieStore.js"); });
  after(() => rmSync(tmp, { recursive: true, force: true }));
  beforeEach(() => {
    rmSync(legacyDir, { recursive: true, force: true });
    rmSync(item, { force: true });
    rmSync(path.join(kc, "mode"), { force: true });
  });

  it("migrates a legacy cookie.json into the Keychain, then retires the legacy copies", async () => {
    seedLegacy();
    const got = await store.loadStored(origin);
    assert.equal(got?.cookie, "overleaf_session2=legacy");
    assert.equal(JSON.parse(readFileSync(item, "utf8")).cookie, "overleaf_session2=legacy");
    assert.equal(existsSync(legacyFile), false);
    assert.equal(existsSync(legacyProfile), false);
  });

  it("retires legacy copies when a Keychain login already exists, without overwriting it", async () => {
    writeFileSync(item, JSON.stringify({ cookie: "overleaf_session2=current", savedAt: 9 }));
    seedLegacy();
    assert.equal((await store.loadStored(origin))?.cookie, "overleaf_session2=current");
    assert.equal(JSON.parse(readFileSync(item, "utf8")).cookie, "overleaf_session2=current");
    assert.equal(existsSync(legacyFile), false);
    assert.equal(existsSync(legacyProfile), false);
    seedLegacy();
    await store.saveStored(origin, "overleaf_session2=fresh");
    assert.equal(JSON.parse(readFileSync(item, "utf8")).cookie, "overleaf_session2=fresh");
    assert.equal(existsSync(legacyFile), false);
    assert.equal(existsSync(legacyProfile), false);
  });

  it("treats a Keychain item without a cookie as absent: the legacy cookie replaces it, never deleted unsaved", async () => {
    for (const bad of ['{"savedAt":1}', '{"cookie":""}', "notjson"]) {
      writeFileSync(item, bad);
      seedLegacy();
      assert.equal((await store.loadStored(origin))?.cookie, "overleaf_session2=legacy", bad);
      assert.equal(JSON.parse(readFileSync(item, "utf8")).cookie, "overleaf_session2=legacy", bad);
      assert.equal(existsSync(legacyFile), false, bad);
    }
  });

  it("keeps the legacy cookie when the Keychain save cannot be verified", async () => {
    seedLegacy();
    writeFileSync(path.join(kc, "mode"), "nosave");
    assert.equal((await store.loadStored(origin))?.cookie, "overleaf_session2=legacy");
    assert.equal(existsSync(legacyFile), true);
  });

  it("logout removes the Keychain item and the legacy copies", async () => {
    await store.saveStored(origin, "overleaf_session2=new");
    seedLegacy();
    assert.equal(await store.clearStored(origin), true);
    assert.equal(existsSync(item), false);
    assert.equal(existsSync(legacyFile), false);
    assert.equal(existsSync(legacyProfile), false);
    seedLegacy(); // legacy copies alone still count as a stored cookie
    assert.equal(await store.clearStored(origin), true);
    assert.equal(existsSync(legacyFile), false);
  });

  it("treats only item-not-found (exit 44) as absent", async () => {
    assert.equal(await store.loadStored(origin), null);
    assert.equal(await store.clearStored(origin), false);
    writeFileSync(item, JSON.stringify({ cookie: "overleaf_session2=kept", savedAt: 1 }));
    writeFileSync(path.join(kc, "mode"), "denied");
    await assert.rejects(store.loadStored(origin), /exit 51/);
    await assert.rejects(store.clearStored(origin), /exit 51/);
    assert.equal(existsSync(item), true);
  });

  it("logout CLI exits nonzero when the Keychain delete fails", () => {
    writeFileSync(item, JSON.stringify({ cookie: "overleaf_session2=kept", savedAt: 1 }));
    writeFileSync(path.join(kc, "mode"), "denied");
    const r = spawnSync(process.execPath, ["--import", "tsx", "src/index.ts", "logout", "--confirm"], {
      cwd: new URL("../../", import.meta.url), env: process.env, encoding: "utf8",
    });
    assert.equal(r.status, 1, r.stdout + r.stderr);
    assert.match(r.stdout, /logout failed/);
    assert.equal(existsSync(item), true);
  });
});

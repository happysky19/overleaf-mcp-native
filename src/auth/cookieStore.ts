// Cookie persistence keyed by Overleaf host.
//
// macOS: the macOS Keychain (service "overleaf-mcp", account = Overleaf host), never on disk. The secret goes to
// `security -i` on stdin (hex-encoded), so it never appears in argv; it is read back with -w.
// Other platforms: a single JSON map at <configDir>/overleaf-mcp/cookie.json with mode 0600 (no encryption, see README).
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";

import { logger } from "../util/logger.js";
import { injectedSessionMode, loadInjectedSession } from "./sessionFd.js";
import { execFile } from "node:child_process";

export interface StoredCookie {
  cookie: string;
  savedAt: number;
}

interface StoreShape {
  hosts: Record<string, StoredCookie>;
}

function configRoot(): string {
  if (process.platform === "darwin") {
    return path.join(os.homedir(), "Library", "Application Support");
  }
  if (process.platform === "win32") {
    return process.env.APPDATA ?? path.join(os.homedir(), "AppData", "Roaming");
  }
  return process.env.XDG_CONFIG_HOME ?? path.join(os.homedir(), ".config");
}

export function cookieFilePath(): string {
  return path.join(configRoot(), "overleaf-mcp", "cookie.json");
}

function hostKey(baseUrl: string): string {
  return new URL(baseUrl).host;
}

async function readStore(): Promise<StoreShape> {
  try {
    const raw = await fs.readFile(cookieFilePath(), "utf8");
    const parsed = JSON.parse(raw) as Partial<StoreShape>;
    return { hosts: parsed.hosts ?? {} };
  } catch (err: unknown) {
    if ((err as NodeJS.ErrnoException)?.code === "ENOENT") return { hosts: {} };
    logger.warn(`cookie store unreadable, treating as empty: ${(err as Error).message}`);
    return { hosts: {} };
  }
}

async function writeStore(store: StoreShape): Promise<void> {
  const file = cookieFilePath();
  await fs.mkdir(path.dirname(file), { recursive: true });
  const tmp = `${file}.tmp`;
  await fs.writeFile(tmp, JSON.stringify(store, null, 2), { mode: 0o600 });
  await fs.chmod(tmp, 0o600);
  await fs.rename(tmp, file);
  await fs.chmod(file, 0o600).catch(() => undefined);
}


const KEYCHAIN = process.platform === "darwin";
const SERVICE = process.env.OL_KEYCHAIN_SERVICE ?? "overleaf-mcp"; // no spaces
export const storeLabel = KEYCHAIN ? `macOS Keychain (service ${SERVICE})` : cookieFilePath();

const NOT_FOUND = 44; // errSecItemNotFound: the only exit that means "no item"

function security(args: string[], input = ""): Promise<{ code: number; out: string; err: string }> {
  return new Promise((resolve) => {
    const p = execFile("security", args, (e, out, err) =>
      resolve({ code: e ? (typeof e.code === "number" ? e.code : -1) : 0, out, err }));
    p.stdin?.end(input);
  });
}

function keychainError(op: string, r: { code: number; err: string }): Error {
  return new Error(`Keychain ${op} failed (security exit ${r.code}): ${r.err.trim()}`);
}

async function keychainFind(baseUrl: string): Promise<StoredCookie | null> {
  const r = await security(["find-generic-password", "-s", SERVICE, "-a", hostKey(baseUrl), "-w"]);
  if (r.code === NOT_FOUND) return null;
  if (r.code !== 0) throw keychainError("read", r);
  // An item without a usable cookie is treated as absent (a valid legacy cookie may then replace it); never as a login.
  try {
    const v = JSON.parse(r.out.trim()) as StoredCookie;
    return typeof v?.cookie === "string" && v.cookie ? v : null;
  } catch { return null; }
}

async function keychainSave(baseUrl: string, item: StoredCookie): Promise<void> {
  const hex = Buffer.from(JSON.stringify(item)).toString("hex");
  await security(["-i"], `add-generic-password -U -s ${SERVICE} -a ${hostKey(baseUrl)} -X ${hex}\n`);
  if ((await keychainFind(baseUrl))?.cookie !== item.cookie) throw new Error("could not save the cookie to the Keychain");
}

// Pre-Keychain installs kept the cookie in cookie.json and a persistent Chrome profile (whose Cookies DB holds the
// session too). Drop this host from cookie.json and remove that profile; true if anything was removed.
async function retireLegacy(baseUrl: string): Promise<boolean> {
  let removed = false;
  const store = await readStore();
  const key = hostKey(baseUrl);
  if (key in store.hosts) {
    delete store.hosts[key];
    if (Object.keys(store.hosts).length) await writeStore(store);
    else await fs.rm(cookieFilePath(), { force: true });
    removed = true;
  }
  const profile = path.join(configRoot(), "overleaf-mcp", "chrome-profile");
  if (await fs.stat(profile).then(() => true, () => false)) {
    await fs.rm(profile, { recursive: true, force: true });
    removed = true;
  }
  return removed;
}

async function retireLegacyQuietly(baseUrl: string): Promise<void> {
  try { await retireLegacy(baseUrl); } catch (err) { logger.warn(`could not remove legacy cookie copies: ${(err as Error).message}`); }
}

export async function loadStored(baseUrl: string): Promise<StoredCookie | null> {
  if (injectedSessionMode) return loadInjectedSession(baseUrl);
  if (KEYCHAIN) {
    const found = await keychainFind(baseUrl);
    if (found) {
      await retireLegacyQuietly(baseUrl); // a verified Keychain login exists: legacy plaintext copies are stale
      return found;
    }
    const legacy = (await readStore()).hosts[hostKey(baseUrl)];
    if (!legacy) return null;
    try {
      await keychainSave(baseUrl, legacy);
    } catch (err) {
      logger.warn(`kept legacy ${cookieFilePath()}: Keychain migration failed: ${(err as Error).message}`);
      return legacy;
    }
    await retireLegacyQuietly(baseUrl);
    return legacy;
  }
  const store = await readStore();
  return store.hosts[hostKey(baseUrl)] ?? null;
}

export async function saveStored(baseUrl: string, cookie: string): Promise<void> {
  if (injectedSessionMode) throw new Error("Injected session cannot be saved to a cookie store.");
  if (KEYCHAIN) {
    await keychainSave(baseUrl, { cookie, savedAt: Date.now() });
    return retireLegacyQuietly(baseUrl);
  }
  const store = await readStore();
  store.hosts[hostKey(baseUrl)] = { cookie, savedAt: Date.now() };
  await writeStore(store);
}

export async function clearStored(baseUrl: string): Promise<boolean> {
  if (injectedSessionMode) throw new Error("Injected session cannot access a cookie store.");
  if (KEYCHAIN) {
    const r = await security(["delete-generic-password", "-s", SERVICE, "-a", hostKey(baseUrl)]);
    if (r.code !== 0 && r.code !== NOT_FOUND) throw keychainError("delete", r);
    return (await retireLegacy(baseUrl)) || r.code === 0;
  }
  const store = await readStore();
  const key = hostKey(baseUrl);
  if (!(key in store.hosts)) return false;
  delete store.hosts[key];
  await writeStore(store);
  return true;
}

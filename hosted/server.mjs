import { createServer } from "node:http";
import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import os from "node:os";
import path from "node:path";
import { randomBytes } from "node:crypto";

const directory = path.dirname(fileURLToPath(import.meta.url));
const publicDirectory = path.join(directory, "public");
const port = Number(process.env.PORT ?? 8080);
const rateLimitPerMinute = Number(process.env.RATE_LIMIT_PER_MINUTE ?? 30);
const dailyCap = Number(process.env.DAILY_CAP ?? 5_000);
const dailyCapPerIp = Number(process.env.DAILY_CAP_PER_IP ?? 300);
const checkerConcurrency = Number(process.env.CHECKER_CONCURRENCY ?? 4);
const checkerQueueTimeoutMs = Number(process.env.CHECKER_QUEUE_TIMEOUT_MS ?? 10_000);
const dailyStateFile =
  process.env.DAILY_STATE_FILE ?? path.join(os.tmpdir(), "bearer-hosted-daily.json");
const killSwitchFile =
  process.env.KILL_SWITCH_FILE ?? path.join(os.tmpdir(), "bearer-hosted-kill");

const config = {
  verifier: process.env.VERIFIER_BIN ?? "zecathon-carrier-verifier",
  attestVerifier: process.env.ATTEST_VERIFIER_BIN ?? process.env.VERIFIER_BIN ?? "zecathon-carrier-verifier",
  primary: process.env.PRIMARY_SERVER ?? "https://na.zec.rocks:443",
  secondary: process.env.SECONDARY_SERVER ?? "https://eu.zec.rocks:443",
  issuerUfvk: process.env.ISSUER_UFVK_FILE ?? "",
  collection: process.env.COLLECTION_ID ?? "",
  items: parseJsonEnv("ITEM_CONFIG_JSON", []),
  holder: parseJsonEnv("HOLDER_CONFIG_JSON", null),
  challengeItem: Number(process.env.CHALLENGE_ITEM ?? 2),
  links: parseJsonEnv("PUBLIC_LINKS_JSON", {
    repo: "https://example.invalid/zecathon-repo",
    evidence: "https://example.invalid/zecathon-evidence",
    video: "https://example.invalid/zecathon-video",
  }),
  attackFixtures: parseJsonEnv("ATTACK_CONFIG_JSON", {}),
  publicRecordsFile:
    process.env.PUBLIC_RECORDS_FILE ?? path.join(directory, "public-records.json"),
};

const requestTimes = new Map();
let activeCheckerRuns = 0;
const checkerQueue = [];
let dailyCapLock = Promise.resolve();

function parseJsonEnv(name, fallback) {
  const value = process.env[name];
  if (!value) return fallback;
  try {
    return JSON.parse(value);
  } catch (error) {
    throw new Error(`${name} must be valid JSON: ${error.message}`);
  }
}

function json(response, status, value) {
  const body = JSON.stringify(value);
  response.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
    "content-length": Buffer.byteLength(body),
  });
  response.end(body);
}

function publicItem(item) {
  return {
    item: item.item,
    label: item.label ?? `Item ${item.item}`,
    txids: item.txids ?? [],
  };
}

function clientAddress(request) {
  return request.headers["x-forwarded-for"]?.split(",")[0]?.trim() ??
    request.socket.remoteAddress ??
    "unknown";
}

function checkRateLimit(request) {
  const now = Date.now();
  const cutoff = now - 60_000;
  const address = clientAddress(request);
  const recent = (requestTimes.get(address) ?? []).filter((time) => time > cutoff);
  if (recent.length >= rateLimitPerMinute) {
    requestTimes.set(address, recent);
    return false;
  }
  recent.push(now);
  requestTimes.set(address, recent);
  return true;
}

function releaseCheckerRun() {
  activeCheckerRuns -= 1;
  while (activeCheckerRuns < checkerConcurrency && checkerQueue.length > 0) {
    const waiter = checkerQueue.shift();
    if (waiter.settled) continue;
    waiter.settled = true;
    clearTimeout(waiter.timer);
    activeCheckerRuns += 1;
    waiter.resolve(releaseCheckerRun);
  }
}

function acquireCheckerRun() {
  if (activeCheckerRuns < checkerConcurrency) {
    activeCheckerRuns += 1;
    return Promise.resolve(releaseCheckerRun);
  }
  return new Promise((resolve) => {
    const waiter = { resolve, settled: false, timer: null };
    waiter.timer = setTimeout(() => {
      waiter.settled = true;
      const index = checkerQueue.indexOf(waiter);
      if (index !== -1) checkerQueue.splice(index, 1);
      resolve(null);
    }, checkerQueueTimeoutMs);
    checkerQueue.push(waiter);
  });
}

async function withCheckerRun(task) {
  const release = await acquireCheckerRun();
  if (!release) {
    const error = new Error("CHECKER_BUSY");
    error.code = "CHECKER_BUSY";
    throw error;
  }
  try {
    return await task();
  } finally {
    release();
  }
}

function killSwitchActive() {
  return existsSync(killSwitchFile);
}

function today() {
  return new Date().toISOString().slice(0, 10);
}

async function consumeDailyCap(address) {
  let unlock;
  const previous = dailyCapLock;
  dailyCapLock = new Promise((resolve) => { unlock = resolve; });
  await previous;
  try {
    let state = { date: today(), count: 0, byAddress: {} };
    try {
      state = JSON.parse(await readFile(dailyStateFile, "utf8"));
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
    }
    if (state.date !== today()) state = { date: today(), count: 0, byAddress: {} };
    const byAddress = state.byAddress && typeof state.byAddress === "object" ? state.byAddress : {};
    if (state.count >= dailyCap || (byAddress[address] ?? 0) >= dailyCapPerIp) return false;
    state.count += 1;
    byAddress[address] = (byAddress[address] ?? 0) + 1;
    state.byAddress = byAddress;
    await mkdir(path.dirname(dailyStateFile), { recursive: true });
    await writeFile(dailyStateFile, JSON.stringify(state), { mode: 0o600 });
    return true;
  } finally {
    unlock();
  }
}

async function readBody(request) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    let settled = false;
    const fail = (error) => {
      if (settled) return;
      settled = true;
      reject(error);
    };
    request.on("data", (chunk) => {
      if (settled) return;
      size += chunk.length;
      if (size > 16_384) {
        fail(new Error("Request body too large"));
        request.destroy();
        return;
      }
      chunks.push(chunk);
    });
    request.once("error", fail);
    request.once("end", () => {
      if (settled) return;
      if (chunks.length === 0) {
        resolve({});
        return;
      }
      try {
        settled = true;
        resolve(JSON.parse(Buffer.concat(chunks).toString("utf8")));
      } catch (error) {
        fail(error);
      }
    });
  });
}

function runVerifierResult(args, timeoutMs = 15_000, verifier = config.verifier) {
  return new Promise((resolve, reject) => {
    const child = spawn(verifier, args, {
      cwd: directory,
      env: { ...process.env, RUST_BACKTRACE: "0" },
      stdio: ["ignore", "pipe", "pipe"],
    });
    const stdout = [];
    const stderr = [];
    let finished = false;
    const timer = setTimeout(() => {
      finished = true;
      child.kill("SIGTERM");
      resolve({
        code: null,
        timedOut: true,
        stdout: Buffer.concat(stdout).toString("utf8").trim(),
        stderr: Buffer.concat(stderr).toString("utf8").trim(),
      });
    }, timeoutMs);
    child.stdout.on("data", (chunk) => stdout.push(chunk));
    child.stderr.on("data", (chunk) => stderr.push(chunk));
    child.once("error", (error) => {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      reject(error);
    });
    child.once("close", (code) => {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      resolve({
        code,
        timedOut: false,
        stdout: Buffer.concat(stdout).toString("utf8").trim(),
        stderr: Buffer.concat(stderr).toString("utf8").trim(),
      });
    });
  });
}

async function runVerifier(args, timeoutMs = 15_000, verifier = config.verifier) {
  const result = await runVerifierResult(args, timeoutMs, verifier);
  if (result.timedOut) throw new Error("Verifier timed out");
  if (result.code !== 0) {
    throw new Error(result.stdout || result.stderr || `Verifier exited with ${result.code}`);
  }
  return result;
}

function configuredItem(number) {
  return config.items.find((item) => item.item === number);
}

async function operationGuard(request) {
  if (killSwitchActive()) return "KILL_SWITCH_ACTIVE";
  if (!checkRateLimit(request)) return "RATE_LIMITED";
  if (!(await consumeDailyCap(clientAddress(request)))) return "DAILY_CAP_REACHED";
  return null;
}

async function verifyItem(request) {
  const itemNumber = Number((await readBody(request)).item);
  const item = configuredItem(itemNumber);
  if (!Number.isSafeInteger(itemNumber) || !item) {
    return { status: 400, body: { error: "Item is not in the allowlist" } };
  }
  const guard = await operationGuard(request);
  if (guard) return { status: 429, body: { error: guard } };
  try {
    const result = await withCheckerRun(() => runVerifier([
      "mainnet-verify-item",
      config.primary,
      config.secondary,
      config.issuerUfvk,
      config.collection,
      String(itemNumber),
      item.txidListFile,
    ]));
    return { status: 200, body: { ok: true, item: publicItem(item), output: result.stdout } };
  } catch (error) {
    return {
      status: error.code === "CHECKER_BUSY" ? 503 : 502,
      body: { ok: false, item: publicItem(item), error: error.message },
    };
  }
}

async function challengeHolder(request) {
  const body = await readBody(request);
  const holder = config.holder;
  if (!holder || body.item !== holder.item) {
    return { status: 400, body: { error: "No holder is configured for that item" } };
  }
  const guard = await operationGuard(request);
  if (guard) return { status: 429, body: { error: guard } };
  const challenge = randomBytes(16).toString("hex");
  const temporaryDirectory = await mkdtemp(path.join(os.tmpdir(), "bearer-proof-"));
  const proofFile = path.join(temporaryDirectory, "proof.json");
  try {
    const result = await withCheckerRun(async () => {
      await runVerifier([
        "mainnet-attest",
        config.primary,
        config.secondary,
        holder.wallet,
        holder.identity,
        holder.txid,
        String(holder.action),
        challenge,
        proofFile,
        config.collection,
        String(holder.item),
        holder.txidListFile,
      ], 15_000, config.attestVerifier);
      return runVerifier([
        "mainnet-proof",
        config.primary,
        config.secondary,
        proofFile,
        challenge,
      ]);
    });
    return {
      status: 200,
      body: { ok: true, item: holder.item, challenge, output: result.stdout },
    };
  } catch (error) {
    return {
      status: error.code === "CHECKER_BUSY" ? 503 : 502,
      body: { ok: false, item: holder.item, challenge, error: error.message },
    };
  } finally {
    await rm(temporaryDirectory, { recursive: true, force: true });
  }
}

async function runAttack(request) {
  const kind = (await readBody(request)).kind;
  const fixture = config.attackFixtures[kind];
  if (!fixture || !["old-proof", "forged-signature", "wrong-key"].includes(kind)) {
    return { status: 400, body: { error: "Unsupported attack kind" } };
  }
  if (!fixture.proofFile || !fixture.challenge) {
    return { status: 503, body: { error: "Attack fixture is not configured" } };
  }
  const guard = await operationGuard(request);
  if (guard) return { status: 429, body: { error: guard } };
  const args = [
    "mainnet-proof",
    config.primary,
    config.secondary,
    fixture.proofFile,
    fixture.challenge,
  ];
  if (fixture.txidListFile) args.push(fixture.txidListFile);
  try {
    const result = await withCheckerRun(() => runVerifierResult(args));
    if (result.timedOut) return { status: 502, body: { error: "Verifier timed out" } };
    return {
      status: 200,
      body: { output: result.stdout || result.stderr || `Verifier exited with ${result.code}` },
    };
  } catch (error) {
    return {
      status: error.code === "CHECKER_BUSY" ? 503 : 502,
      body: { error: error.message },
    };
  }
}

async function publicRecords() {
  try {
    return JSON.parse(await readFile(config.publicRecordsFile, "utf8"));
  } catch (error) {
    return { error: `Public records unavailable: ${error.message}` };
  }
}

async function serveStatic(request, response, pathname) {
  const requested = pathname === "/" ? "/index.html" : pathname;
  const file = path.resolve(publicDirectory, `.${requested}`);
  if (!file.startsWith(`${publicDirectory}${path.sep}`)) return json(response, 404, { error: "Not found" });
  try {
    const data = await readFile(file);
    const contentType = file.endsWith(".html")
      ? "text/html; charset=utf-8"
      : file.endsWith(".js")
        ? "text/javascript; charset=utf-8"
        : file.endsWith(".svg")
        ? "image/svg+xml"
        : "text/css; charset=utf-8";
    response.writeHead(200, { "content-type": contentType, "cache-control": "no-store" });
    response.end(data);
  } catch {
    json(response, 404, { error: "Not found" });
  }
}

const server = createServer(async (request, response) => {
  try {
    const url = new URL(request.url, `http://${request.headers.host ?? "localhost"}`);
    if (request.method === "GET" && url.pathname === "/api/collection") {
      return json(response, 200, {
        collection: config.collection,
        items: config.items.map(publicItem),
        challengeAvailable: Boolean(config.holder),
        challengeItem: config.challengeItem,
        links: config.links,
        records: await publicRecords(),
      });
    }
    if (request.method === "POST" && url.pathname === "/api/verify-item") {
      const result = await verifyItem(request);
      return json(response, result.status, result.body);
    }
    if (request.method === "POST" && url.pathname === "/api/challenge") {
      const result = await challengeHolder(request);
      return json(response, result.status, result.body);
    }
    if (request.method === "POST" && url.pathname === "/api/attack") {
      const result = await runAttack(request);
      return json(response, result.status, result.body);
    }
    if (request.method === "GET") return serveStatic(request, response, url.pathname);
    return json(response, 405, { error: "Method not allowed" });
  } catch (error) {
    return json(response, 400, { error: error.message });
  }
});

server.listen(port, () => {
  console.log(`Bearer hosted page listening on ${port}`);
});

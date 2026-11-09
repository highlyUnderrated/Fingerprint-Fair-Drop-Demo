const express = require("express");
const path = require("path");

const PORT = Number(process.env.PORT || 8081);
const DROP_ID = "nov-2026-aurora-drop";
const SKU = "AURORA-X1-LTD";
const DEMO_MODE = process.env.NODE_ENV !== "production";
const EVENT_MAX_AGE_MS = 2 * 60 * 1000;
const MAX_FUTURE_SKEW_MS = 30 * 1000;

const purchases = new Map();
const usedEventIds = new Set();
const attempts = [];

function normalizeRegion(value = "ap") {
  const region = String(value).trim().toLowerCase();

  if (["ap", "asia", "ap-south-1", "mumbai"].includes(region)) return "ap";
  if (["eu", "europe", "frankfurt"].includes(region)) return "eu";
  return "us";
}

const region = normalizeRegion(process.env.FINGERPRINT_REGION);
const serverApiBaseUrls = {
  us: "https://api.fpjs.io",
  eu: "https://eu.api.fpjs.io",
  ap: "https://ap.api.fpjs.io",
};

function readSecretFromTerminal() {
  return new Promise((resolve, reject) => {
    if (!process.stdin.isTTY || typeof process.stdin.setRawMode !== "function") {
      reject(
        new Error(
          "FINGERPRINT_SECRET_KEY is missing. Start in an interactive terminal or provide the environment variable."
        )
      );
      return;
    }

    process.stdout.write("Fingerprint Server API secret key (input hidden): ");
    process.stdin.setRawMode(true);
    process.stdin.resume();
    process.stdin.setEncoding("utf8");

    let secret = "";

    const cleanup = () => {
      process.stdin.removeListener("data", onData);
      process.stdin.setRawMode(false);
      process.stdin.pause();
      process.stdout.write("\n");
    };

    const onData = (chunk) => {
      for (const character of chunk) {
        if (character === "\u0003") {
          cleanup();
          process.exit(130);
        }

        if (character === "\r" || character === "\n") {
          cleanup();
          if (!secret.trim()) {
            reject(new Error("A Server API secret key is required."));
          } else {
            resolve(secret.trim());
          }
          return;
        }

        if (character === "\u007f" || character === "\b") {
          secret = secret.slice(0, -1);
          continue;
        }

        secret += character;
      }
    };

    process.stdin.on("data", onData);
  });
}

async function getSecretKey() {
  const environmentSecret = process.env.FINGERPRINT_SECRET_KEY?.trim();
  return environmentSecret || readSecretFromTerminal();
}

function toBoolean(value) {
  if (typeof value === "boolean") return value;
  if (value && typeof value === "object" && "result" in value) {
    return Boolean(value.result);
  }
  return false;
}

function signalValue(value, fallback = "unknown") {
  if (value === undefined || value === null) return fallback;
  if (typeof value === "object" && "result" in value) return value.result;
  return value;
}

function toTimestampMs(value) {
  if (value === undefined || value === null || value === "") return null;

  const numeric = Number(value);
  if (Number.isFinite(numeric)) {
    return numeric < 1_000_000_000_000 ? numeric * 1000 : numeric;
  }

  const parsed = Date.parse(String(value));
  return Number.isFinite(parsed) ? parsed : null;
}

function normalizeEvent(event) {
  const identification =
    event.identification || event.products?.identification?.data || {};
  const botProduct = event.products?.botd?.data?.bot;
  const proxyProduct = event.products?.proxy?.data;
  const vpnProduct = event.products?.vpn?.data;
  const tamperingProduct = event.products?.tampering?.data;

  const bot = signalValue(
    event.bot ?? event.bot_detection?.bot ?? botProduct,
    "not_detected"
  );

  const normalizedBot = String(bot);

  return {
    visitorId:
      identification.visitor_id ||
      identification.visitorId ||
      event.visitor_id ||
      event.visitorId,
    visitorFound:
      identification.visitor_found ?? identification.visitorFound ?? null,
    confidence:
      identification.confidence?.score ??
      event.confidence?.score ??
      event.confidence_score ??
      null,
    eventId: event.event_id || event.requestId || null,
    timestamp: event.timestamp || event.time || null,
    timestampMs: toTimestampMs(event.timestamp || event.time),
    linkedId: event.linked_id || event.linkedId || null,
    tags: event.tags || event.tag || {},
    ipAddress:
      event.ip_address || identification.ip_address || event.ip || "Unavailable",
    bot: normalizedBot,
    botType:
      normalizedBot === "bad" || normalizedBot === "good"
        ? event.bot_type || botProduct?.type || "automation"
        : null,
    proxy: toBoolean(event.proxy ?? proxyProduct),
    proxyConfidence:
      event.proxy_confidence || proxyProduct?.confidence || "unknown",
    proxyType:
      event.proxy_details?.proxy_type ||
      proxyProduct?.details?.proxy_type ||
      null,
    vpn: toBoolean(event.vpn ?? vpnProduct),
    tampering: toBoolean(event.tampering ?? tamperingProduct),
    replayed: toBoolean(event.replayed),
    highActivity: toBoolean(
      event.high_activity_device ?? event.products?.high_activity_device?.data
    ),
    suspectScore: Number(event.suspect_score ?? event.suspectScore ?? 0),
  };
}

function publicSignalSummary(signals) {
  return {
    bot: signals.bot,
    botType: signals.botType,
    proxy: signals.proxy,
    proxyConfidence: signals.proxyConfidence,
    proxyType: signals.proxyType,
    vpn: signals.vpn,
    tampering: signals.tampering,
    replayed: signals.replayed,
    highActivity: signals.highActivity,
    suspectScore: signals.suspectScore,
  };
}

function applyDemoScenario(observed, scenario) {
  const effective = { ...observed };

  if (!DEMO_MODE || scenario === "live") return effective;

  if (scenario === "trusted") {
    effective.bot = "not_detected";
    effective.botType = null;
    effective.proxy = false;
    effective.proxyConfidence = "high";
    effective.proxyType = null;
    effective.vpn = false;
    effective.tampering = false;
    effective.replayed = false;
    effective.highActivity = false;
    effective.suspectScore = 0;
  }

  if (scenario === "proxy") {
    effective.proxy = true;
    effective.proxyConfidence = "high";
    effective.proxyType = "residential";
  }

  if (scenario === "bot") {
    effective.bot = "bad";
    effective.botType = "selenium";
  }

  return effective;
}

function buildDecision({ signals, observed, visitorId, eventId, accountId, now = Date.now() }) {
  const purchaseKey = `${DROP_ID}:${visitorId}`;
  const priorPurchase = purchases.get(purchaseKey) || null;
  const trace = [];

  trace.push({
    rule: "Verified Fingerprint event",
    outcome: "pass",
    detail: "The event was retrieved directly from the Fingerprint Server API.",
  });

  const contextMatches =
    observed.eventId === eventId &&
    observed.linkedId === accountId &&
    observed.tags?.action === "limited_drop_checkout" &&
    observed.tags?.drop_id === DROP_ID &&
    observed.tags?.sku === SKU;

  if (!contextMatches) {
    trace.push({
      rule: "Checkout context",
      outcome: "fail",
      detail: "The verified event does not match this account, drop, SKU, or checkout action.",
    });
    return {
      decision: "deny",
      title: "Checkout blocked",
      reason: "The identification event is not bound to this checkout request.",
      nextStep: "Generate a new event for the current account and checkout action.",
      trace,
      priorPurchase,
    };
  }

  trace.push({
    rule: "Checkout context",
    outcome: "pass",
    detail: "Account, action, drop, and SKU match the verified event.",
  });

  if (usedEventIds.has(eventId)) {
    trace.push({
      rule: "Fresh event",
      outcome: "fail",
      detail: "This event ID has already been used for a checkout attempt.",
    });
    return {
      decision: "deny",
      title: "Checkout blocked",
      reason: "The identification event was replayed.",
      nextStep: "Generate a new identification event and try again.",
      trace,
      priorPurchase,
    };
  }

  const eventAgeMs = observed.timestampMs === null ? null : now - observed.timestampMs;
  if (
    eventAgeMs === null ||
    eventAgeMs > EVENT_MAX_AGE_MS ||
    eventAgeMs < -MAX_FUTURE_SKEW_MS
  ) {
    trace.push({
      rule: "Fresh event",
      outcome: "fail",
      detail: "The verified event is missing a valid timestamp or falls outside the two-minute checkout window.",
    });
    return {
      decision: "deny",
      title: "Checkout expired",
      reason: "The identification event is too old or has an invalid timestamp.",
      nextStep: "Generate a fresh identification event and retry the checkout.",
      trace,
      priorPurchase,
    };
  }

  trace.push({
    rule: "Fresh event",
    outcome: "pass",
    detail: "The event is recent and its ID has not been used before.",
  });

  if (signals.replayed || signals.tampering) {
    trace.push({
      rule: "Request integrity",
      outcome: "fail",
      detail: "Replay or browser tampering was detected.",
    });
    return {
      decision: "deny",
      title: "Checkout blocked",
      reason: "The request failed the integrity check.",
      nextStep: "Ask the shopper to retry in a trusted browser.",
      trace,
      priorPurchase,
    };
  }

  trace.push({
    rule: "Request integrity",
    outcome: "pass",
    detail: "No replay or browser tampering signal was detected.",
  });

  if (signals.bot === "bad" || signals.bot === "good") {
    trace.push({
      rule: "Human checkout",
      outcome: "fail",
      detail: `Bot classification: ${signals.bot}${signals.botType ? ` (${signals.botType})` : ""}.`,
    });
    return {
      decision: "deny",
      title: "Automated checkout blocked",
      reason: "Transactional checkout is reserved for human shoppers.",
      nextStep: "Do not reserve inventory or create an order.",
      trace,
      priorPurchase,
    };
  }

  trace.push({
    rule: "Human checkout",
    outcome: "pass",
    detail: "Fingerprint did not classify the visitor as a bot.",
  });

  if (priorPurchase) {
    trace.push({
      rule: "One device, one item",
      outcome: "fail",
      detail: `This device already purchased the drop as ${priorPurchase.accountId}.`,
    });
    return {
      decision: "deny",
      title: "Duplicate order prevented",
      reason:
        "The same device has already purchased this limited-edition item, even though the account changed.",
      nextStep: "Keep the inventory available for another customer.",
      trace,
      priorPurchase,
    };
  }

  trace.push({
    rule: "One device, one item",
    outcome: "pass",
    detail: "No successful purchase exists for this device and drop.",
  });

  if (signals.proxy || signals.vpn) {
    trace.push({
      rule: "Network trust",
      outcome: "review",
      detail: signals.proxy
        ? `${signals.proxyConfidence} confidence ${signals.proxyType || ""} proxy detected.`.trim()
        : "VPN usage detected.",
    });
    return {
      decision: "review",
      title: "Step-up verification required",
      reason:
        "The shopper is using network-obfuscation technology. This is a risk signal, not proof of fraud.",
      nextStep: "Verify payment, phone, or shipping identity before reserving inventory.",
      trace,
      priorPurchase,
    };
  }

  if (signals.highActivity || signals.suspectScore >= 20) {
    trace.push({
      rule: "Risk threshold",
      outcome: "review",
      detail: signals.highActivity
        ? "High device activity was detected."
        : `Suspect Score ${signals.suspectScore} reached the demo review threshold.`,
    });
    return {
      decision: "review",
      title: "Additional verification required",
      reason: "The device risk level is higher than the automatic-approval threshold.",
      nextStep: "Apply a low-friction challenge or send the order for review.",
      trace,
      priorPurchase,
    };
  }

  trace.push({
    rule: "Risk threshold",
    outcome: "pass",
    detail: "The device is below the demo review threshold.",
  });

  return {
    decision: "approve",
    title: "Order approved",
    reason: "The device is eligible for this limited-edition drop.",
    nextStep: "Reserve one item and record the successful purchase against this device.",
    trace,
    priorPurchase,
  };
}

async function fetchFingerprintEvent(secretKey, eventId) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10000);

  try {
    const response = await fetch(
      `${serverApiBaseUrls[region]}/v4/events/${encodeURIComponent(eventId)}`,
      {
        headers: {
          Authorization: `Bearer ${secretKey}`,
          Accept: "application/json",
        },
        signal: controller.signal,
      }
    );

    const payload = await response.json().catch(() => ({}));

    if (!response.ok) {
      const message =
        response.status === 403
          ? "Fingerprint rejected the Server API key or workspace region."
          : payload?.error?.message || `Fingerprint Server API returned ${response.status}.`;
      const error = new Error(message);
      error.status = response.status;
      throw error;
    }

    return payload;
  } finally {
    clearTimeout(timeout);
  }
}

function rememberAttempt(attempt) {
  attempts.unshift(attempt);
  if (attempts.length > 20) attempts.length = 20;
}

async function start() {
  const secretKey = await getSecretKey();
  const app = express();

  app.disable("x-powered-by");
  app.use((req, res, next) => {
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
    next();
  });
  app.use(express.json({ limit: "20kb" }));
  app.use("/api", (req, res, next) => {
    res.setHeader("Cache-Control", "no-store");
    next();
  });

  app.get("/api/health", (req, res) => {
    res.json({
      status: "ready",
      region,
      serverApi: serverApiBaseUrls[region],
      demoMode: DEMO_MODE,
      dropId: DROP_ID,
      sku: SKU,
    });
  });

  app.get("/api/demo/state", (req, res) => {
    res.json({
      purchaseCount: purchases.size,
      attemptCount: attempts.length,
      attempts,
    });
  });

  app.post("/api/demo/reset", (req, res) => {
    if (!DEMO_MODE) {
      res.status(404).json({ error: "Not found." });
      return;
    }

    purchases.clear();
    usedEventIds.clear();
    attempts.length = 0;
    res.json({ status: "reset" });
  });

  app.post("/api/checkout", async (req, res) => {
    const eventId = String(req.body?.eventId || "").trim();
    const accountId = String(req.body?.accountId || "").trim();
    const fullName = String(req.body?.fullName || "").trim();
    const requestedScenario = String(req.body?.scenario || "live").trim();
    const scenario = ["live", "trusted", "proxy", "bot"].includes(requestedScenario)
      ? requestedScenario
      : "live";

    if (!eventId || !accountId || !fullName) {
      res.status(400).json({
        error: "eventId, accountId, and fullName are required.",
      });
      return;
    }

    try {
      const rawEvent = await fetchFingerprintEvent(secretKey, eventId);
      const observedSignals = normalizeEvent(rawEvent);

      if (!observedSignals.visitorId) {
        res.status(422).json({
          error: "Fingerprint did not return a visitor ID for this event.",
        });
        return;
      }

      const effectiveSignals = applyDemoScenario(observedSignals, scenario);
      const decision = buildDecision({
        signals: effectiveSignals,
        observed: observedSignals,
        visitorId: observedSignals.visitorId,
        eventId,
        accountId,
      });

      usedEventIds.add(eventId);

      let orderId = null;
      if (decision.decision === "approve") {
        orderId = `ORD-${Date.now().toString(36).toUpperCase()}`;
        purchases.set(`${DROP_ID}:${observedSignals.visitorId}`, {
          orderId,
          accountId,
          fullName,
          purchasedAt: new Date().toISOString(),
        });
      }

      const attempt = {
        id: `ATT-${Date.now().toString(36).toUpperCase()}`,
        timestamp: new Date().toISOString(),
        accountId,
        eventId,
        visitorId: observedSignals.visitorId,
        decision: decision.decision,
        reason: decision.reason,
        scenario,
        simulated: DEMO_MODE && scenario !== "live",
      };
      rememberAttempt(attempt);

      res.json({
        ...decision,
        orderId,
        dropId: DROP_ID,
        sku: SKU,
        accountId,
        eventId,
        visitorId: observedSignals.visitorId,
        effectiveSignals: publicSignalSummary(effectiveSignals),
        scenario,
        simulated: DEMO_MODE && scenario !== "live",
      });
    } catch (error) {
      console.error("Checkout verification failed:", error.message);
      res.status(error.status === 404 ? 422 : 502).json({
        error: error.message || "Unable to verify the Fingerprint event.",
      });
    }
  });

  app.use(express.static(path.join(__dirname, "public")));
  app.get("*", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "index.html"));
  });

  app.listen(PORT, "127.0.0.1", () => {
    console.log(`\nMobile Store demo: http://localhost:${PORT}`);
    console.log(`Fingerprint region: ${region} (${serverApiBaseUrls[region]})`);
    console.log("Secret key loaded in process memory only.\n");
  });
}

start().catch((error) => {
  console.error(error.message);
  process.exit(1);
});

const FINGERPRINT_PUBLIC_KEY = "r5A6Kjds9fWALIoVqgk6";
const FINGERPRINT_REGION = "ap";

const elements = {
  form: document.querySelector("#checkoutForm"),
  accountId: document.querySelector("#accountId"),
  fullName: document.querySelector("#fullName"),
  checkoutButton: document.querySelector("#checkoutButton"),
  scenario: document.querySelector("#scenario"),
  resetButton: document.querySelector("#resetButton"),
  emptyResult: document.querySelector("#emptyResult"),
  result: document.querySelector("#result"),
  decisionLabel: document.querySelector("#decisionLabel"),
  decisionHeadline: document.querySelector("#decisionHeadline"),
  decisionReason: document.querySelector("#decisionReason"),
  nextStep: document.querySelector("#nextStep"),
  decisionIcon: document.querySelector("#decisionIcon"),
  signalGrid: document.querySelector("#signalGrid"),
  policyTrace: document.querySelector("#policyTrace"),
  simulationNotice: document.querySelector("#simulationNotice"),
  secondAccountButton: document.querySelector("#secondAccountButton"),
  serverStatus: document.querySelector("#serverStatus"),
  serverStatusDot: document.querySelector("#serverStatusDot"),
  attemptCount: document.querySelector("#attemptCount"),
  activityBody: document.querySelector("#activityBody"),
  toast: document.querySelector("#toast"),
  steps: [
    document.querySelector("#stepIdentify"),
    document.querySelector("#stepVerify"),
    document.querySelector("#stepDecide"),
  ],
};

let agentPromise;
let agentStartedAt = 0;

function initializeFingerprint() {
  if (!agentPromise) {
    agentStartedAt = Date.now();
    agentPromise = import(`https://fpjscdn.net/v4/${FINGERPRINT_PUBLIC_KEY}`)
      .then((Fingerprint) => Fingerprint.start({ region: FINGERPRINT_REGION }))
      .catch((error) => {
        agentPromise = null;
        throw error;
      });
  }

  return agentPromise;
}

function wait(milliseconds) {
  return new Promise((resolve) => window.setTimeout(resolve, milliseconds));
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function compactId(value, size = 7) {
  if (!value) return "Unavailable";
  if (value.length <= size * 2 + 3) return value;
  return `${value.slice(0, size)}...${value.slice(-size)}`;
}

function formatTime(value) {
  return new Intl.DateTimeFormat(undefined, {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  }).format(new Date(value));
}

function setStep(index, state) {
  elements.steps[index].classList.remove("active", "complete");
  if (state) elements.steps[index].classList.add(state);
}

function resetProgress() {
  elements.steps.forEach((_, index) => setStep(index, null));
}

function setLoading(isLoading, label = "Verify device & place order") {
  elements.checkoutButton.disabled = isLoading;
  elements.checkoutButton.classList.toggle("loading", isLoading);
  elements.checkoutButton.querySelector("span").textContent = label;
}

function showToast(message, kind = "neutral") {
  elements.toast.textContent = message;
  elements.toast.dataset.kind = kind;
  elements.toast.classList.add("visible");
  window.clearTimeout(showToast.timeout);
  showToast.timeout = window.setTimeout(() => {
    elements.toast.classList.remove("visible");
  }, 3200);
}

async function requestJson(url, options) {
  const response = await fetch(url, options);
  const payload = await response.json().catch(() => ({}));

  if (!response.ok) {
    throw new Error(payload.error || `Request failed with status ${response.status}.`);
  }

  return payload;
}

function signalCard(label, value, state = "neutral") {
  return `
    <div class="signal-card" data-state="${state}">
      <span>${escapeHtml(label)}</span>
      <strong>${escapeHtml(value)}</strong>
    </div>
  `;
}

function renderDecision(data) {
  elements.emptyResult.hidden = true;
  elements.result.hidden = false;
  elements.result.dataset.decision = data.decision;

  const labels = {
    approve: "Approved",
    deny: "Denied",
    review: "Review",
  };
  const icons = {
    approve: "✓",
    deny: "×",
    review: "!",
  };

  elements.decisionLabel.textContent = labels[data.decision] || "Decision";
  elements.decisionHeadline.textContent = data.title;
  elements.decisionReason.textContent = data.reason;
  elements.nextStep.textContent = data.nextStep;
  elements.decisionIcon.textContent = icons[data.decision] || "?";
  elements.simulationNotice.hidden = !data.simulated;

  const signals = data.effectiveSignals;
  const proxyLabel = signals.proxy
    ? `${signals.proxyType || "proxy"} / ${signals.proxyConfidence}`
    : "Not detected";
  const botLabel = signals.bot === "not_detected" ? "Not detected" : signals.bot;

  elements.signalGrid.innerHTML = [
    signalCard("Visitor ID", compactId(data.visitorId), "good"),
    signalCard("Bot", botLabel, signals.bot === "not_detected" ? "good" : "bad"),
    signalCard("Proxy", proxyLabel, signals.proxy ? "warn" : "good"),
    signalCard("VPN", signals.vpn ? "Detected" : "Not detected", signals.vpn ? "warn" : "good"),
    signalCard(
      "Suspect Score",
      String(signals.suspectScore),
      signals.suspectScore >= 20 ? "warn" : "good"
    ),
    signalCard("Event ID", compactId(data.eventId), "neutral"),
    signalCard("Order ID", data.orderId || "Not created", data.orderId ? "good" : "neutral"),
  ].join("");

  elements.policyTrace.innerHTML = data.trace
    .map(
      (item) => `
        <li data-outcome="${escapeHtml(item.outcome)}">
          <span></span>
          <div><strong>${escapeHtml(item.rule)}</strong><small>${escapeHtml(item.detail)}</small></div>
        </li>
      `
    )
    .join("");

  elements.secondAccountButton.hidden = data.decision !== "approve";
}

function renderActivity(attempts) {
  elements.attemptCount.textContent = `${attempts.length} ${attempts.length === 1 ? "attempt" : "attempts"}`;

  if (!attempts.length) {
    elements.activityBody.innerHTML =
      '<tr class="empty-row"><td colspan="5">No checkout attempts yet.</td></tr>';
    return;
  }

  elements.activityBody.innerHTML = attempts
    .map(
      (attempt) => `
        <tr>
          <td>${escapeHtml(formatTime(attempt.timestamp))}</td>
          <td>${escapeHtml(attempt.accountId)}</td>
          <td><code>${escapeHtml(compactId(attempt.visitorId, 5))}</code></td>
          <td>${escapeHtml(attempt.simulated ? `${attempt.scenario} (simulated)` : attempt.scenario)}</td>
          <td><span class="table-decision" data-decision="${escapeHtml(attempt.decision)}">${escapeHtml(attempt.decision)}</span></td>
        </tr>
      `
    )
    .join("");
}

async function refreshState() {
  const state = await requestJson("/api/demo/state");
  renderActivity(state.attempts);
}

async function checkHealth() {
  try {
    const health = await requestJson("/api/health");
    elements.serverStatus.textContent = `Decision service ready / ${health.region.toUpperCase()} region`;
    elements.serverStatusDot.classList.add("online");
    await refreshState();
  } catch (error) {
    elements.serverStatus.textContent = "Decision service unavailable";
    elements.serverStatusDot.classList.add("offline");
  }
}

elements.form.addEventListener("submit", async (event) => {
  event.preventDefault();
  resetProgress();
  elements.emptyResult.hidden = false;
  elements.result.hidden = true;

  try {
    setLoading(true, "Identifying this device...");
    setStep(0, "active");

    const agent = await initializeFingerprint();
    const remainingWarmup = 1000 - (Date.now() - agentStartedAt);
    if (remainingWarmup > 0) await wait(remainingWarmup);
    const fingerprintResult = await agent.get({
      linkedId: elements.accountId.value.trim(),
      tags: {
        action: "limited_drop_checkout",
        drop_id: "nov-2026-aurora-drop",
        sku: "AURORA-X1-LTD",
      },
    });

    const eventId = fingerprintResult.event_id || fingerprintResult.requestId;
    if (!eventId) throw new Error("Fingerprint did not return an event ID.");

    setStep(0, "complete");
    setStep(1, "active");
    setLoading(true, "Verifying trusted signals...");

    const decision = await requestJson("/api/checkout", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        eventId,
        accountId: elements.accountId.value.trim(),
        fullName: elements.fullName.value.trim(),
        scenario: elements.scenario.value,
      }),
    });

    setStep(1, "complete");
    setStep(2, "complete");
    renderDecision(decision);
    await refreshState();
    showToast(decision.title, decision.decision);
  } catch (error) {
    resetProgress();
    elements.emptyResult.hidden = false;
    elements.emptyResult.querySelector("strong").textContent = "Unable to complete verification";
    elements.emptyResult.querySelector("p").textContent = error.message;
    showToast(error.message, "deny");
  } finally {
    setLoading(false);
  }
});

elements.secondAccountButton.addEventListener("click", () => {
  const match = elements.accountId.value.match(/^(.*?)(?:-(\d+))?$/);
  const base = match?.[1] || "customer";
  const next = Number(match?.[2] || 1) + 1;
  elements.accountId.value = `${base}-${String(next).padStart(3, "0")}`;
  elements.accountId.focus();
  showToast("Account changed. The physical device is still the same.");
});

elements.resetButton.addEventListener("click", async () => {
  elements.resetButton.disabled = true;
  try {
    await requestJson("/api/demo/reset", { method: "POST" });
    elements.accountId.value = "customer-001";
    elements.scenario.value = "trusted";
    elements.emptyResult.hidden = false;
    elements.result.hidden = true;
    elements.emptyResult.querySelector("strong").textContent = "Ready for a checkout";
    elements.emptyResult.querySelector("p").textContent =
      "The decision and supporting evidence will appear here.";
    resetProgress();
    await refreshState();
    showToast("Demo data reset. The next clean device checkout can be approved.", "approve");
  } catch (error) {
    showToast(error.message, "deny");
  } finally {
    elements.resetButton.disabled = false;
  }
});

initializeFingerprint().catch(() => {
  // The checkout action surfaces a useful error if the agent cannot load.
});
checkHealth();

const $ = (id) => document.getElementById(id);

const TEXT = {
  safe: ["Safe", "This link looks genuine.", "\u2713"],
  suspicious: ["Suspicious", "Be careful with this link.", "!"],
  phishing: ["Phishing", "Do not open this link.", "\u2715"],
};

// Optional: if the web app is running locally, use its full scan (live checks + AI).
const BACKENDS = ["http://127.0.0.1:5000/api/scan", "http://localhost:5000/api/scan"];
const BACKEND_TIMEOUT_MS = 25000;

let tabUrl = "";

(async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  tabUrl = (tab && tab.url) || "";
  if (!/^https?:\/\//i.test(tabUrl)) {
    $("current").textContent = "This page can't be scanned (not a regular web page).";
    $("btn").disabled = true;
    return;
  }
  $("current").textContent = tabUrl;
  $("btn").addEventListener("click", run);
})();

async function run() {
  $("error").hidden = true;
  $("btn").disabled = true;
  $("btn").textContent = "Checking\u2026";
  try {
    show(localScan(tabUrl), false);
    const full = await fullScan(tabUrl);
    if (full) show(full, true);
  } catch (err) {
    $("error").textContent = "Could not analyse this page.";
    $("error").hidden = false;
  } finally {
    $("btn").disabled = false;
    $("btn").textContent = "Check this page";
  }
}

// Same result shape as the web app's /api/scan, built from rules.js alone.
function localScan(url) {
  const r = analyseUrl(url);
  const f = r.features;
  return {
    verdict: r.verdict,
    findings: [
      ...r.reasons.map((t) => ({ t, ok: false })),
      ...r.positives.map((t) => ({ t, ok: true })),
    ].slice(0, 5),
    domain: f.hostIsIp ? f.host : f.registeredDomain,
    https: f.usesHttps,
    ai: null,
  };
}

async function fullScan(url) {
  for (const endpoint of BACKENDS) {
    try {
      const res = await fetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url }),
        signal: AbortSignal.timeout(BACKEND_TIMEOUT_MS),
      });
      if (res.ok) return await res.json();
    } catch (err) {
      // server not running: keep the local result
    }
  }
  return null;
}

function show(d, full) {
  const [label, sub, icon] = TEXT[d.verdict];
  $("result").dataset.v = d.verdict;
  $("label").textContent = label;
  $("sub").textContent = sub;
  $("icon").textContent = icon;
  $("findings").replaceChildren(
    ...d.findings.map((f) =>
      Object.assign(document.createElement("li"), { textContent: f.t, className: f.ok ? "ok" : "" })
    )
  );
  $("domain").textContent = d.domain;
  $("https").textContent = d.https ? "HTTPS" : "No HTTPS";
  $("mode").textContent = full ? "Full scan" : "Local rules";
  $("mode").classList.toggle("full", full);
  const note = d.ai && d.ai.explanation;
  $("ai").hidden = !note;
  if (note) $("ai").replaceChildren(Object.assign(document.createElement("b"), { textContent: "AI: " }), note);
  $("result").hidden = false;
}

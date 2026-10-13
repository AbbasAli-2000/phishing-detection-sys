const currentUrlEl = document.getElementById("current-url");
const checkBtn = document.getElementById("check-btn");
const result = document.getElementById("result");
const errorBox = document.getElementById("error");
const engineBadge = document.getElementById("engine-badge");

const VERDICT_TEXT = {
  safe: "Looks safe",
  suspicious: "Suspicious",
  phishing: "Phishing",
};

const BACKEND_URLS = ["http://127.0.0.1:5000/api/scan", "http://localhost:5000/api/scan"];
const BACKEND_TIMEOUT_MS = 1500;

let activeUrl = "";

init();

async function init() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  activeUrl = tab && tab.url ? tab.url : "";

  if (!activeUrl || !/^https?:\/\//i.test(activeUrl)) {
    currentUrlEl.textContent = "This page can't be scanned (not a regular web page).";
    checkBtn.disabled = true;
    return;
  }

  currentUrlEl.textContent = activeUrl;
  checkBtn.addEventListener("click", runCheck);
}

async function runCheck() {
  errorBox.hidden = true;
  checkBtn.disabled = true;
  checkBtn.textContent = "Checking…";

  try {
    const local = analyseUrl(activeUrl);
    render(local, null);

    const ai = await tryBackend(activeUrl);
    if (ai) {
      engineBadge.textContent = "Rules + AI";
      engineBadge.classList.add("on");
      render(local, ai);
    }
  } catch (err) {
    errorBox.textContent = "Could not analyse this URL.";
    errorBox.hidden = false;
  } finally {
    checkBtn.disabled = false;
    checkBtn.textContent = "Check this page";
  }
}

async function tryBackend(url) {
  for (const endpoint of BACKEND_URLS) {
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), BACKEND_TIMEOUT_MS);
      const response = await fetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url }),
        signal: controller.signal,
      });
      clearTimeout(timer);
      if (!response.ok) continue;
      const data = await response.json();
      return data.ai || null;
    } catch (err) {
      // backend not running or unreachable — silently fall back to local rules
    }
  }
  return null;
}

function render(local, ai) {
  result.dataset.verdict = local.verdict;
  document.getElementById("verdict-label").textContent = VERDICT_TEXT[local.verdict];
  document.getElementById("score-value").textContent = local.score;
  document.getElementById("meter-fill").style.width = local.score + "%";

  const findings = document.getElementById("findings");
  findings.innerHTML = "";
  local.reasons.forEach((r) => findings.appendChild(item(r, false)));
  local.positives.forEach((p) => findings.appendChild(item(p, true)));

  const aiBlock = document.getElementById("ai-block");
  if (ai) {
    aiBlock.hidden = false;
    document.getElementById("ai-verdict").textContent =
      `${VERDICT_TEXT[ai.verdict] || ai.verdict} · confidence ${ai.confidence}%`;
    document.getElementById("ai-explanation").textContent = ai.explanation || "";
  } else {
    aiBlock.hidden = true;
  }

  result.hidden = false;
}

function item(text, isGood) {
  const li = document.createElement("li");
  li.textContent = text;
  if (isGood) li.classList.add("good");
  return li;
}

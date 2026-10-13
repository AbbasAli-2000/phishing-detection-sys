const $ = (id) => document.getElementById(id);

const TEXT = {
  safe: ["Safe", "This link looks genuine.", "\u2713"],
  suspicious: ["Suspicious", "Be careful with this link.", "!"],
  phishing: ["Phishing", "Do not open this link.", "\u2715"],
};

$("form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const url = $("url").value.trim();
  $("error").hidden = true;
  if (!url) return;

  $("btn").disabled = true;
  $("btn").textContent = "Checking\u2026";
  try {
    const res = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error);
    show(data);
  } catch (err) {
    $("result").hidden = true;
    $("error").textContent = err.message || "Could not reach the server.";
    $("error").hidden = false;
  } finally {
    $("btn").disabled = false;
    $("btn").textContent = "Check";
  }
});

function show(d) {
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
  $("live").hidden = d.live;
  $("result").hidden = false;
}
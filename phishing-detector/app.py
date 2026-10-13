import os
from concurrent.futures import ThreadPoolExecutor

from flask import Flask, jsonify, render_template, request

import detector
import live
import openrouter_client

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

app = Flask(__name__)
RANK = {"safe": 0, "suspicious": 1, "phishing": 2}


@app.after_request
def cors(resp):  # lets the Chrome extension call this API
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type"
    return resp


def ask_ai(url, features):
    if not openrouter_client.is_configured():
        return None
    try:
        return openrouter_client.analyse(url, features)
    except openrouter_client.OpenRouterError:
        return None  # fall back to rules + live checks


@app.route("/")
def index():
    return render_template("index.html")


@app.post("/api/scan")
def scan():
    url = detector.normalise((request.get_json(silent=True) or {}).get("url", ""))
    if not url or not detector.is_valid(url):
        return jsonify({"error": "Enter a valid web address, e.g. example.com/login"}), 400

    result = detector.analyse(url)
    f = result["features"]
    with ThreadPoolExecutor(1) as pool:
        ai_job = pool.submit(ask_ai, url, f)  # AI and live checks run at the same time
        pts, bad, good, live_ok = live.check(url, f)
        ai = ai_job.result()

    verdict = detector.verdict_from_score(min(result["score"] + pts, 100))
    if ai and RANK[ai["verdict"]] > RANK[verdict]:
        verdict = ai["verdict"]

    findings = [{"t": t, "ok": False} for t in bad + result["reasons"]]
    findings += [{"t": t, "ok": True} for t in good + result["positives"]]
    return jsonify({
        "url": url,
        "verdict": verdict,
        "findings": findings[:5],
        "domain": f["host"] if f["host_is_ip"] else f["registered_domain"],
        "https": f["uses_https"],
        "live": live_ok,
        "ai": ai,
    })


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
import os

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
    pts, bad, good, live_ok = live.check(url, f)
    verdict = detector.verdict_from_score(min(result["score"] + pts, 100))

    ai = None
    if openrouter_client.is_configured():
        try:
            ai = openrouter_client.analyse(url, f)
            if RANK[ai["verdict"]] > RANK[verdict]:
                verdict = ai["verdict"]
        except openrouter_client.OpenRouterError:
            pass  # fall back to rules + live checks

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
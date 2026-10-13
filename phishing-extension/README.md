# Phishing Detector — Chrome Extension

Checks the current tab's URL for phishing patterns using the same rule engine
as the web app. Works standalone (no server needed); if your Flask app
(`python app.py`) is running on `localhost:5000`, it also shows the AI review.

## Install (unpacked, for development / FYP demo)

1. Open Chrome and go to: `chrome://extensions`
2. Turn on **Developer mode** (top-right toggle)
3. Click **Load unpacked**
4. Select this `phishing-extension` folder
5. The shield icon appears in your toolbar (pin it for easy access)

## Use

1. Open any website
2. Click the extension icon
3. Click **Check this page**
4. See the verdict, risk score, and reasons

If the Flask app is running locally, an **AI review** section appears too,
and the badge switches from "Rules only" to "Rules + AI".

## Files

| File | Purpose |
|---|---|
| `manifest.json` | Extension configuration (Manifest V3) |
| `popup.html` / `popup.css` | Popup interface |
| `rules.js` | Standalone rule-based detector (JS port of `detector.py`) |
| `popup.js` | Reads the active tab, runs `rules.js`, optionally calls the Flask API |
| `icons/` | Toolbar icons |

# AI Based Phishing Website Detection System

Final Year Project I — Department of Computer Science, SIMT
Ahmed Bin Liaquat, Abbas Ali · Supervisor: Dr. Razi Ahmed

User ek URL enter karta hai, system uska structure analyse karta hai aur real time
mein batata hai ke link safe hai, suspicious hai, ya phishing.

## Kaise kaam karta hai

1. **Request Handling Module** (`app.py`) — Flask route `/api/scan` URL receive aur validate karta hai.
2. **Feature + Rule Module** (`detector.py`) — URL se 18+ features nikaalta hai (IP host, `@` symbol,
   subdomain count, hyphens, suspicious TLD, punycode, brand keywords, login/verify words, HTTPS,
   URL length) aur 0–100 ka risk score banata hai.
3. **API Integration Module** (`openrouter_client.py`) — wohi URL aur features OpenRouter API ko
   bhejta hai aur model se JSON verdict leta hai.
4. **Response Processing** — dono verdicts combine hote hain; jo zyada cautious ho wohi final hota hai.
   API key na ho to system sirf rule engine se kaam karta rehta hai.

Verdict thresholds: score ≥ 55 → phishing, ≥ 28 → suspicious, warna safe.

## Setup

```bash
pip install -r requirements.txt
cp .env.example .env        # phir .env mein apni OpenRouter key daalein
python app.py
```

Browser mein: http://localhost:5000

AI ke baghair bhi app chalti hai — top-right badge "Rules only" dikhayega.
Key daalne ke baad badge "Rules + AI" ho jayega.

## API

```
POST /api/scan
{ "url": "http://apple.id-verify.account-locked.tk/signin" }
```

Response mein: `verdict`, `risk_score`, `reasons`, `positives`, `features`, `ai`.

```
GET /api/health   → { "status": "ok", "ai_enabled": true|false }
```

## Files

| File | Kaam |
|---|---|
| `app.py` | Flask server, routes, verdict combination |
| `detector.py` | Feature extraction + rule-based scoring |
| `openrouter_client.py` | OpenRouter API integration |
| `templates/index.html` | Web interface |
| `static/css/style.css` | Styling |
| `static/js/main.js` | Scan request aur result rendering |

## Limitation

System sirf URL ka structure parhta hai, page ka content load nahi karta.
Ye jaan boojh kar rakha gaya hai — unknown page kholna khud ek risk hai.

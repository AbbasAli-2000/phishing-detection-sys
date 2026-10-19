# AI Based Phishing Website Detection System

Final Year Project I — Department of Computer Science, SIMT
Ahmed Bin Liaquat, Abbas Ali · Supervisor: Dr. Razi Ahmed

User ek URL enter karta hai, system uska structure parhta hai, live internet checks karta hai
(DNS, SSL, domain age, redirects) aur real time mein batata hai ke link safe hai, suspicious hai,
ya phishing — saath mein wajah (evidence) bhi dikhata hai.

## Kaise kaam karta hai

1. **Request Handling Module** (`app.py`) — Flask route `/api/scan` URL receive aur validate karta hai
   (bina `https://` wala link `https` maan leta hai), baqi modules ko chalata hai aur final verdict banata hai.
2. **Feature + Rule Module** (`detector.py`) — URL se features nikaalta hai (IP host, `@` symbol,
   subdomain count, hyphens, suspicious TLD, punycode, URL shortener, brand keywords, login/verify words,
   HTTPS, URL length) aur risk points banata hai.
3. **Live Check Module** (`live.py`) — link ko asli internet par check karta hai:
   - DNS: domain exist karta hai ya nahi
   - SSL certificate: valid hai ya expired/fake, aur kis ne issue kiya
   - Domain age (RDAP): kuch din purana domain phishing ka bada signal hai
   - Redirects: link aakhir mein kahan le jata hai
   - Google Safe Browsing: optional, key chahiye

   Internet na ho to ye checks skip ho jate hain aur kisi link ko galat penalty nahi milti.
4. **API Integration Module** (`openrouter_client.py`) — wohi URL aur features OpenRouter API ko
   bhejta hai aur model se JSON verdict leta hai. Ye live checks ke saath **ek hi waqt** mein chalta hai.
5. **Response Processing** (`app.py`) — rules aur live checks ke points jod kar 0–100 score banta hai.
   AI verdict ko sirf zyada cautious bana sakta hai, kam nahi. API key na ho ya AI fail ho jaye to
   system rules aur live checks se kaam karta rehta hai.

Verdict thresholds: score ≥ 55 → phishing, ≥ 28 → suspicious, warna safe.
(Score andar istemal hota hai, screen par nahi dikhta.)

## Ek scan ka flow

```
Browser (main.js)  →  app.py  →  detector.py        (URL rules)
                              →  live.py            ┐ ek saath
                              →  openrouter_client.py ┘ (optional AI)
                      app.py (verdict combine)  →  Browser (main.js)  →  screen par result
```

## Setup

```bash
pip install -r requirements.txt
copy .env.example .env      # Mac/Linux: cp .env.example .env
python app.py
```

Browser mein: http://localhost:5000

Keys optional hain — `.env` mein daalein (`.env` GitHub par upload nahi hoti, `.gitignore` rokti hai):

```
OPENROUTER_API_KEY=apni-key            # https://openrouter.ai/keys
OPENROUTER_MODEL=nvidia/nemotron-3-ultra-550b-a55b:free
GOOGLE_SAFE_BROWSING_KEY=apni-key      # Google Cloud Console, Safe Browsing API
```

`OPENROUTER_MODEL` mein model ki **ID** likhein (https://openrouter.ai/models se), display naam nahi.
`:free` wale models free hain lekin roz ki limit hoti hai. Bade models slow hote hain — tez scan ke liye
chhota model chunein, `openrouter/free` use karein, ya key hata dein (phir AI skip ho jata hai).

## API

```
POST /api/scan
{ "url": "example.com/login" }
```

Response mein: `verdict`, `findings` (har ek mein `t` text aur `ok` true/false), `domain`, `https`,
`live` (offline ho to false), `ai` (use na hua ho to null).

## Files — kaun si file ka kya role hai

### Web app (`phishing-detector/`)

| File | Role |
|---|---|
| `app.py` | Flask server. Page serve karta hai, `/api/scan` receive karta hai, baqi modules ko chalata hai aur final verdict banata hai |
| `detector.py` | URL ko ghoor kar rules se points deta hai (bina internet ke). URL normalise/validate bhi yahi karta hai |
| `live.py` | Asli internet checks: DNS, SSL, domain age, redirects, Safe Browsing. Local/private addresses ko kabhi fetch nahi karta |
| `openrouter_client.py` | Optional AI check. OpenRouter API se verdict leta hai, galat/khali jawab ko safely handle karta hai |
| `templates/index.html` | Web page ka structure (input, check button, result area) |
| `static/css/style.css` | Page ki design: glass card, colors, verdict ke rang |
| `static/js/main.js` | URL bhejta hai `/api/scan` par aur result screen par dikhata hai |
| `static/img/bg.svg` | Background artwork |
| `requirements.txt` | Python packages ki list (Flask, requests, python-dotenv, gunicorn) |
| `.env.example` | Keys ka template (isme asli key kabhi na likhein) |
| `.env` | Aap ki apni local file jisme asli keys hoti hain — GitHub par nahi jati |
| `.gitignore` | Git ko batati hai `.env` aur cache files upload na kare |
| `README.md` | Ye file |

### Chrome extension (`phishing-extension/`)

| File | Role |
|---|---|
| `manifest.json` | Extension ki settings aur permissions |
| `popup.html` / `popup.css` | Toolbar icon dabane par khulne wala chhota window aur uski design |
| `popup.js` | Current tab ka URL leta hai, `rules.js` chalata hai, aur app chal rahi ho to AI review bhi mangta hai |
| `rules.js` | `detector.py` ke rules ka JavaScript version, taake extension akela bhi kaam kare |
| `icons/` | Toolbar ke icons |

## Limitation

- System links ka structure aur live signals dekhta hai, page ka content load nahi karta.
  Ye jaan boojh kar rakha gaya hai — unknown page kholna khud ek risk hai.
- Live checks scanned site ko ek request bhejte hain (sirf headers), is liye us site ko server ka IP nazar aa sakta hai.
- Free hosting (jaise PythonAnywhere free plan) par outbound internet limited hota hai, wahan live checks aur AI
  aksar skip ho jate hain aur app rules par chalti hai.
- Domain age ka check domain ke aakhri do hisse use karta hai, is liye `example.co.uk` jaise domains mein
  ghalat parh sakta hai — isay hint samjhein.
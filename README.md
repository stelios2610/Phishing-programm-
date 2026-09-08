# PhishGuard

Τοπικός ανιχνευτής **phishing URL** για Microsoft 365 / Outlook / Azure και δεκάδες άλλα brands (Google, Apple, τράπεζες, gov.gr, PayPal, crypto, logistics).

Ο σύνδεσμος **δεν ανοίγεται και δεν στέλνεται σε τρίτους**. Η ανάλυση γίνεται μόνο στο κείμενο του URL: host, path, query, IDN/homograph, typosquatting.

Κανένα εργαλείο δεν είναι 100%. Αν αμφιβάλλετε, μην συνδεθείτε.

## Τι εντοπίζει

- Επίσημα domains Microsoft (`microsoftonline.com`, `office.com`, `outlook.com`, `azure.com`, …) έναντι απομιμήσεων
- Brand ως subdomain: `login.microsoft.com.evil.xyz`
- Κόλπο `@`: `https://microsoft.com@attacker.test/`
- Typosquat / leetspeak: `micros0ft-online.com`
- Homograph / punycode (`xn--`)
- Raw IP + brand στο path
- Δωρεάν hosting (`web.app`, `github.io`, `netlify.app`, …)
- Ύποπτα TLD, HTTP σε σελίδες login, shorteners, αόρατους χαρακτήρες

## Εγκατάσταση

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Χρήση

CLI:

```bash
phishguard "https://login.microsoft.com.secure-auth.xyz/signin"
phishguard --json "https://login.microsoftonline.com/"
```

Web UI (δεν κάνει fetch των URLs που επικολλάτε):

```bash
phishguard --serve --host 127.0.0.1 --port 8000
```

Ανοίξτε http://127.0.0.1:8000

## API

`POST /api/analyze` με JSON `{"url":"..."}`.

## Tests

```bash
pytest -q
```

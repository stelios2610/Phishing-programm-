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

## Windows εφαρμογή (MSI)

Κατέβασε το installer από τη **ρίζα του repo** (φαίνεται στην πρώτη σελίδα στο GitHub):

- [`PhishGuard-Setup.msi`](PhishGuard-Setup.msi) (~12 MB, Windows 10/11 64-bit)
- [`release/msi-phishscan.zip`](release/msi-phishscan.zip) — το ίδιο σε zip

Το παράθυρο Windows κατεβάζει σύντομα το HTML (χωρίς login) για να πιάσει ψεύτικες φόρμες κωδικού.

Εντοπίζει και δολώματα σε **αληθινό SharePoint/OneDrive** (όνομα αρχείου «ασφαλές μήνυμα / click to view»), όχι μόνο ψεύτικα domains.

Διπλό κλικ στο MSI → εγκατάσταση στο `C:\Program Files\PhishGuard\`. Άνοιξε **PhishGuard** από το μενού Έναρξη ή τρέξε:

`C:\Program Files\PhishGuard\PhishGuard.exe`

Είναι κανονικό παράθυρο Windows (όχι browser). Ο σύνδεσμος δεν ανοίγεται.

Για να ξαναχτίσεις το MSI σε Linux:

```bash
sudo apt-get install mingw-w64 msitools wixl
bash packaging/windows/build_msi.sh
```

## Εγκατάσταση (Python / web / CLI)

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

Web UI:

```bash
phishguard --serve --host 127.0.0.1 --port 8000
```

Παράθυρο εφαρμογής (tkinter):

```bash
phishguard --desktop
```

Ανοίξτε http://127.0.0.1:8000

## API

`POST /api/analyze` με JSON `{"url":"..."}`.

## Tests

```bash
pytest -q
```

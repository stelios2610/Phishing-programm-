# Privacy policy — PhishGuard

Last updated: 2026-09-09

PhishGuard is a **defensive phishing URL checker**. It is not an antivirus and it does not catch every fake website.

## What the app does

You paste or share a URL. The app scores the URL on the device (domain tricks, brand impersonation, SharePoint/OneDrive filename lures). It may then download **HTML only** of that URL from your device (no login, no JavaScript execution) to look for password forms and fake brand pages.

## Data we collect

- **We do not create accounts.**
- **We do not send your URLs to our servers.** There is no PhishGuard backend.
- The URL you check stays on your phone except when the app fetches that same URL over the internet to read its HTML.
- We do not sell data. We do not show ads. We do not use analytics SDKs.

## Permissions

- **Internet:** to fetch the HTML of the URL you asked to check (and only that). Cleartext HTTP is allowed because phishing kits often use `http://`.

## Children

The app is not directed at children under 13.

## Contact

Open an issue on the project repository: https://github.com/stelios2610/Phishing-programm-

## Limits

No tool is 100%. If you are unsure, do not enter a password. Kits that draw the login form only with JavaScript can still slip through.

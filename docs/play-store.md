# Google Play — PhishGuard

Package: `com.phishguard.scanner`  
Version: 1.0.0 (versionCode 1)

This agent cannot upload to Play for you. You need a Google Play Console developer account and an **upload keystore** that you keep private.

## Privacy policy URL (required)

Play requires a public HTTPS privacy policy. After this file is on `main`:

https://github.com/stelios2610/Phishing-programm-/blob/main/docs/privacy-policy.md

If Play rejects the GitHub page, enable GitHub Pages on this repo and point to the same markdown, or host `docs/privacy-policy.md` on any HTTPS site you control.

## Data safety form

- Data collected: none by the developer.
- The app fetches the user-submitted URL from the device (network access to that host only).
- No account, no location, no contacts, no advertising ID.
- App does not share data with third parties.

## Store listing (EL)

**Τίτλος:** PhishGuard — έλεγχος phishing URL

**Σύντομη:** Ελέγξτε συνδέσμους Microsoft 365, τραπεζών, gov.gr και άλλων brands πριν πατήσετε σύνδεση.

**Πλήρης:** Το PhishGuard αναλύει το URL στο κινητό σας (typosquatting, κόλπο @, απομίμηση brand, δολώματα SharePoint/OneDrive) και διαβάζει μόνο το HTML της σελίδας, χωρίς login και χωρίς JavaScript. Δεν είναι 100%. Αν αμφιβάλλετε, μην συνδεθείτε.

**Windows:** υπάρχει και εγκατάσταση MSI στον υπολογιστή από το ίδιο project στο GitHub.

## Store listing (EN)

**Title:** PhishGuard — phishing URL checker

**Short:** Check Microsoft 365, bank, gov.gr and other brand links before you sign in.

**Full:** PhishGuard scores the URL on your phone (typosquatting, @ tricks, brand impersonation, SharePoint/OneDrive filename lures) and downloads HTML only — no login, no JavaScript. Nothing is 100%. If you doubt it, do not sign in.

## Build a release AAB

On a machine with Android Studio / Android SDK:

```bash
cd android
# create a keystore once:
# keytool -genkey -v -keystore upload-keystore.jks -keyalg RSA -keysize 2048 -validity 10000 -alias phishguard
cp keystore.properties.example keystore.properties
# fill passwords, then in app/build.gradle.kts wire signingConfigs from that file
./gradlew bundleRelease
```

Ready-made signed Play file: [`release/PhishGuard-Play.aab`](../release/PhishGuard-Play.aab)

Keep the upload `.jks` private. It is not in the repo. Without it you cannot ship updates.

If you rebuild locally, upload `app/build/outputs/bundle/release/app-release.aab`.

Debug APK (sideload test):

```bash
cd android
./gradlew assembleDebug
```

## Content rating / target

Utility / security. No user-generated content. Not a VPN. Not a device admin app.

## Screenshots

Run the app, paste the built-in examples (official Microsoft vs subdomain trap vs SharePoint-style lure) and capture the result screen in Greek and English.

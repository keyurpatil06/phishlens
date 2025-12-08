# 🛡️ PhishGuard – Chrome Extension

A lightweight **Manifest V3 Chrome Extension** that detects phishing attempts in Gmail and Outlook Web.  
Uses local heuristics and free API (VirusTotal) to analyze email content and links.  
View results at your **Next.js dashboard** for more details.

---

## 🚀 Features

- ✅ Detects spoofed sender names, typosquatted domains, punycode, and suspicious TLDs
- ⚡ Works offline with local heuristics
- 🌐 Cloud checks via VirusTotal and Gemini based URL check (add-on feature)
- 📊 Sends scan results to your dashboard (one POST endpoint)

---

## 🧩 Installation

1. Clone or download this folder locally:
   ```bash
   git clone https://github.com/keyurpatil06/phishlens.git
   ```
2. Open Chrome and navigate to:
   ```bash
   chrome://extensions
   ```
3. Enable Developer mode (top right).

4. Click Load unpacked → select the Extensions folder.

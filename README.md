# 🛡️ PhishGuard – Chrome Extension

A lightweight **Manifest V3 Chrome Extension** that detects phishing attempts in Gmail and Outlook Web.  
Uses local heuristics and optional free APIs (Google Safe Browsing, VirusTotal) to analyze email content and links.  
Can also send results to your **Next.js dashboard**.

---

## 🚀 Features

- ✅ Detects spoofed sender names, typosquatted domains, punycode, and suspicious TLDs  
- ⚡ Works offline with local heuristics  
- 🌐 Optional cloud checks via Google Safe Browsing + VirusTotal  
- 🧠 Non-intrusive banner in Gmail/Outlook  
- 📊 Sends scan results to your dashboard (one POST endpoint)  
- 🔁 Retry queue for offline submissions  

---

## 🧩 Installation

1. Clone or download this folder locally:  
   ```bash
   git clone https://github.com/<your-repo>/phish-guard
2. Open Chrome and navigate to: 
    ```bash
    chrome://extensions
3. Enable Developer mode (top right).

4. Click Load unpacked → select the phish-guard folder.
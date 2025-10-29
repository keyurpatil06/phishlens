function withActiveTab(fn) {
  chrome.tabs.query({ active: true, currentWindow: true }, tabs => fn(tabs[0]));
}

withActiveTab(tab => {
  if (!tab?.id) return;

  chrome.tabs.sendMessage(tab.id, { type: "PG_GET_RESULT" }, (data) => {
    // If content script isn't present (e.g., not on Gmail/Outlook)
    if (chrome.runtime.lastError) {
      document.getElementById("status").textContent = "Open an email to analyze.";
      return;
    }

    const status = document.getElementById("status");
    const reasonsEl = document.getElementById("reasons");
    reasonsEl.innerHTML = "";

    if (!data) { status.textContent = "Open an email to analyze."; return; }

    status.textContent = `Risk: ${data.level.toUpperCase()} (score ${data.score})`;
    (data.reasons || []).slice(0, 6).forEach(r => {
      const li = document.createElement("li");
      li.textContent = r;
      reasonsEl.appendChild(li);
    });
  });
});

function saveScanToHistory(result) {
  chrome.storage.local.get(["history"], data => {
    const history = data.history || [];

    history.unshift({
      score: result.score,
      level: result.level,
      stats: result.stats || { malicious: 0, suspicious: 0, undetected: 0, harmless: 0 },
      timestamp: Date.now()
    });

    chrome.storage.local.set({ history });
  });
}
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
    saveScanToHistory(data);
    (data.reasons || []).slice(0, 6).forEach(r => {
      const li = document.createElement("li");
      li.textContent = r;
      reasonsEl.appendChild(li);
    });
  });
});
// LOAD GRAPHS FROM HISTORY WHEN POPUP OPENS
document.addEventListener("DOMContentLoaded", function () {
  chrome.storage.local.get(["history"], data => {
    const history = data.history || [];
    if (history.length === 0) return;

    // GRAPH 1: SCORE OVER TIME
    const labels = history.map(e => new Date(e.timestamp).toLocaleTimeString());
    const values = history.map(e => e.score);

    new Chart(document.getElementById("scoreChart"), {
      type: "line",
      data: {
        labels,
        datasets: [{
          label: "Risk Score",
          data: values,
          borderWidth: 2
        }]
      }
    });

    // GRAPH 2: DETECTION SUMMARY
    

    // REAL detection summary based on risk levels
// REAL detection summary based on history (dynamic)
const riskCounts = { HIGH: 0, MEDIUM: 0, LOW: 0 };

history.forEach(h => {
  const lvl = h.level?.toUpperCase() || "LOW";
  if (riskCounts[lvl] !== undefined) {
    riskCounts[lvl]++;
  }
});

new Chart(document.getElementById("summaryChart"), {
  type: "bar",
  data: {
    labels: ["High Risk", "Medium Risk", "Low Risk"],
    datasets: [{
      label: "Scans",
      data: [
        riskCounts.HIGH,
        riskCounts.MEDIUM,
        riskCounts.LOW
      ],
      borderWidth: 2
    }]
  }
});


  });
});

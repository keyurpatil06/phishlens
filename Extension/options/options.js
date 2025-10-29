const fields = ["DASHBOARD_URL", "DASHBOARD_TOKEN", "GSB_API_KEY", "VT_API_KEY"];
chrome.storage.sync.get(fields, vals => {
    fields.forEach(f => { const el = document.getElementById(f); if (el && vals[f]) el.value = vals[f]; });
});

document.getElementById("save").addEventListener("click", () => {
    const payload = {};
    fields.forEach(f => payload[f] = document.getElementById(f).value.trim());
    chrome.storage.sync.set(payload, () => {
        const msg = document.getElementById("msg");
        msg.textContent = "Saved!";
        setTimeout(() => msg.textContent = "", 1500);
    });
});

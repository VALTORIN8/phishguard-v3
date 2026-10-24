// "Back to safety" landing page. The flagged hostname is shown as text only.
const site = new URLSearchParams(location.search).get("site");
if (site) document.getElementById("site").textContent = site.slice(0, 253);
document.getElementById("closeTab").addEventListener("click", () => {
  chrome.tabs.getCurrent(tab => {
    if (tab?.id !== undefined) chrome.tabs.remove(tab.id);
    else window.close();
  });
});

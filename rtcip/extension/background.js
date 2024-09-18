console.log("Background script started");

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "IP_EXTRACTED") {
    console.log("IP extracted:", message.ip);
  }
});

chrome.action.onClicked.addListener((tab) => {
  console.log("Extension icon clicked");
  chrome.runtime.sendMessage({type: "CREATE_PROXY"});
});

console.log("Background script loaded");
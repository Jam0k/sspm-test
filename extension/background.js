console.log("Background script started");

let config = null;
let browserUUID = null;
let sessionId = null;

// Load config, generate UUID and session ID
chrome.storage.local.get(['config', 'browserUUID'], function(result) {
  if (result.config) {
    config = result.config;
    console.log("Config loaded:", config);
  } else {
    console.log("Config not found, loading from file");
    loadConfig();
  }
  
  if (result.browserUUID) {
    browserUUID = result.browserUUID;
    console.log("Existing browser UUID:", browserUUID);
  } else {
    browserUUID = generateUUID();
    chrome.storage.local.set({browserUUID: browserUUID});
    console.log("New browser UUID generated:", browserUUID);
  }

  // Always generate a new session ID when the script starts
  sessionId = generateSessionId();
  console.log("New session ID generated:", sessionId);
});

function loadConfig() {
  fetch(chrome.runtime.getURL('config.json'))
    .then(response => response.json())
    .then(data => {
      config = data;
      chrome.storage.local.set({config: config});
      console.log("Config loaded and saved:", config);
    })
    .catch(error => console.error('Error loading config:', error));
}

function generateUUID() {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
    var r = Math.random() * 16 | 0, v = c == 'x' ? r : (r & 0x3 | 0x8);
    return v.toString(16);
  });
}

function generateSessionId() {
  return Date.now().toString();
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "SYNC_DEVICE") {
    console.log("Sync requested with IP:", message.ip);
    registerOrUpdateDevice(message.ip, sendResponse);
    return true;  // Indicates we will send a response asynchronously
  }
});

function registerOrUpdateDevice(ip, sendResponse) {
  if (!config || !browserUUID || !sessionId) {
    console.log("Config, browserUUID, or sessionId not available, retrying in 5 seconds");
    setTimeout(() => registerOrUpdateDevice(ip, sendResponse), 5000);
    return;
  }

  const endpoint = `${config.server_ip}/register-device`;
  
  fetch(endpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': config.api_key
    },
    body: JSON.stringify({
      uuid: browserUUID,
      internal_ip: ip,
      session_id: sessionId
    })
  })
  .then(response => response.json())
  .then(data => {
    console.log("Device registration/update response:", data);
    // Start heartbeat after successful registration
    setupHeartbeat();
    sendResponse({success: true});
  })
  .catch(error => {
    console.error('Error registering/updating device:', error);
    sendResponse({success: false});
  });
}

function setupHeartbeat() {
  chrome.alarms.create('heartbeat', { periodInMinutes: 5 });
}

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === 'heartbeat') {
    sendHeartbeat();
  }
});

function sendHeartbeat() {
  if (!config || !browserUUID || !sessionId) {
    console.log("Config, browserUUID, or sessionId not available for heartbeat");
    return;
  }

  const endpoint = `${config.server_ip}/heartbeat`;
  
  fetch(endpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': config.api_key
    },
    body: JSON.stringify({
      uuid: browserUUID,
      session_id: sessionId
    })
  })
  .then(response => response.json())
  .then(data => console.log("Heartbeat response:", data))
  .catch(error => console.error('Error sending heartbeat:', error));
}

console.log("Background script loaded");
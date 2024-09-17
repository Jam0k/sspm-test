let serverUrl = '';
let apiKey = '';
let uuid = '';
let internalIp = '';
let sessionId = '';

function generateUUID() {
  return ([1e7]+-1e3+-4e3+-8e3+-1e11).replace(/[018]/g, c =>
    (c ^ crypto.getRandomValues(new Uint8Array(1))[0] & 15 >> c / 4).toString(16)
  );
}

function generateSessionId() {
  return Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
}

async function registerOrUpdateDevice() {
  try {
    console.log('Registering/updating device with:', { uuid, internalIp, sessionId });
    const response = await fetch(`${serverUrl}/register-device`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-API-Key': apiKey
      },
      body: JSON.stringify({
        uuid,
        internal_ip: internalIp,
        session_id: sessionId
      }),
    });
    
    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`HTTP error! status: ${response.status}, message: ${errorText}`);
    }
    
    const responseData = await response.json();
    console.log('Device registered/updated successfully:', responseData);
  } catch (error) {
    console.error('Failed to register/update device:', error);
  }
}

async function initializeExtension() {
  console.log('Initializing extension...');
  
  // Load config
  try {
    const response = await fetch(chrome.runtime.getURL('config.json'));
    const config = await response.json();
    apiKey = config.apiKey;
    serverUrl = config.serverUrl;
    console.log('Loaded config:', { serverUrl, apiKey: apiKey.substring(0, 5) + '...' });
  } catch (error) {
    console.error('Failed to load config:', error);
    return;
  }

  // Generate or retrieve UUID
  try {
    const result = await new Promise(resolve => chrome.storage.local.get(['uuid'], resolve));
    if (result.uuid) {
      uuid = result.uuid;
    } else {
      uuid = generateUUID();
      await new Promise(resolve => chrome.storage.local.set({ uuid }, resolve));
    }
    console.log('UUID:', uuid);
  } catch (error) {
    console.error('Failed to get/set UUID:', error);
    return;
  }

  // Generate session ID
  sessionId = generateSessionId();
  console.log('Session ID:', sessionId);

  // Inject content script to get internal IP
  chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
    if (tabs[0]) {
      chrome.tabs.executeScript(tabs[0].id, {file: 'content.js'});
    }
  });

  console.log('Extension initialized');
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'setInternalIp') {
    internalIp = message.ip;
    console.log('Internal IP set:', internalIp);
    registerOrUpdateDevice();
  }
});

chrome.runtime.onInstalled.addListener(initializeExtension);
chrome.runtime.onStartup.addListener(initializeExtension);

// Periodic updates
setInterval(async () => {
  chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
    if (tabs[0]) {
      chrome.tabs.executeScript(tabs[0].id, {file: 'content.js'});
    }
  });
}, 5 * 60 * 1000); // Every 5 minutes
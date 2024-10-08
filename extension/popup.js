console.log("Popup script started");

let localConnection;
let sendChannel;

function createProxyConnection() {
  console.log("Creating proxy connection");
  localConnection = new RTCPeerConnection();
  
  sendChannel = localConnection.createDataChannel("sendChannel");
  sendChannel.onopen = handleSendChannelStatusChange;
  sendChannel.onclose = handleSendChannelStatusChange;
  
  localConnection.onicecandidate = e => {
    console.log("New ICE candidate:", e.candidate);
    if (e.candidate) {
      const ip = extractIPFromCandidate(e.candidate);
      if (ip) {
        console.log("Extracted IP:", ip);
        document.getElementById('ipAddress').textContent = ip;
        // Store the IP in chrome.storage instead of sending message immediately
        chrome.storage.local.set({lastExtractedIP: ip});
      }
    }
  };
  
  console.log("Creating offer");
  localConnection.createOffer().then(
    gotDescription,
    onCreateSessionDescriptionError
  );
}

function extractIPFromCandidate(candidate) {
  const ipRegex = /([0-9]{1,3}(\.[0-9]{1,3}){3}|[a-f0-9]{1,4}(:[a-f0-9]{1,4}){7})/;
  const match = ipRegex.exec(candidate.candidate);
  return match ? match[1] : null;
}

function gotDescription(desc) {
  console.log("Got local description:", desc);
  localConnection.setLocalDescription(desc);
}

function onCreateSessionDescriptionError(error) {
  console.error("Failed to create session description: ", error);
}

function handleSendChannelStatusChange(event) {
  if (sendChannel) {
    console.log("Send channel state changed to:", sendChannel.readyState);
  }
}

document.getElementById('syncButton').addEventListener('click', function() {
  chrome.storage.local.get('lastExtractedIP', function(result) {
    if (result.lastExtractedIP) {
      chrome.runtime.sendMessage({type: "SYNC_DEVICE", ip: result.lastExtractedIP}, function(response) {
        if (response && response.success) {
          document.getElementById('syncMessage').textContent = "Sync successful!";
        } else {
          document.getElementById('syncMessage').textContent = "Sync failed. Please try again.";
        }
      });
    } else {
      document.getElementById('syncMessage').textContent = "No IP detected. Please wait and try again.";
    }
  });
});

chrome.storage.local.get('browserUUID', function(result) {
  if (result.browserUUID) {
    document.getElementById('browserUUID').textContent = result.browserUUID;
  }
});

createProxyConnection();

console.log("Popup script loaded");
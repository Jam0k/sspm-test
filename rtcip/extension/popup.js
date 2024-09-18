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
        chrome.runtime.sendMessage({type: "IP_EXTRACTED", ip: ip});
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

document.getElementById('refreshButton').addEventListener('click', createProxyConnection);

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "CREATE_PROXY") {
    createProxyConnection();
  }
});

createProxyConnection();

console.log("Popup script loaded");
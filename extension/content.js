function getInternalIp() {
    return new Promise((resolve, reject) => {
      const pc = new RTCPeerConnection({
        iceServers: [{ urls: 'stun:stun.l.google.com:19302' }]
      });
      pc.createDataChannel('');
      pc.createOffer()
        .then(offer => pc.setLocalDescription(offer))
        .catch(err => reject(err));
  
      pc.onicecandidate = (ice) => {
        if (!ice || !ice.candidate || !ice.candidate.candidate) return;
        
        const regexResult = /([0-9]{1,3}(\.[0-9]{1,3}){3}|[a-f0-9]{1,4}(:[a-f0-9]{1,4}){7})/.exec(ice.candidate.candidate);
        const ip = regexResult ? regexResult[1] : null;
        
        if (ip) {
          console.log('Internal IP found:', ip);
          resolve(ip);
          pc.close();
        }
      };
  
      setTimeout(() => {
        reject(new Error('Timeout getting internal IP'));
        pc.close();
      }, 5000);
    });
  }
  
  getInternalIp().then(ip => {
    chrome.runtime.sendMessage({ action: 'setInternalIp', ip: ip });
  }).catch(error => {
    console.error('Failed to get internal IP:', error);
  });
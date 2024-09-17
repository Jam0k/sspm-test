document.addEventListener('DOMContentLoaded', function() {
  const uuidSpan = document.getElementById('uuid');
  const internalIpSpan = document.getElementById('internalIp');
  const lastSeenSpan = document.getElementById('lastSeen');
  const refreshDevicesButton = document.getElementById('refreshDevices');
  const deviceListDiv = document.getElementById('deviceList');

  // Load current device information
  chrome.storage.local.get(['uuid', 'internalIp', 'lastSeen'], function(result) {
      uuidSpan.textContent = result.uuid || 'Not available';
      internalIpSpan.textContent = result.internalIp || 'Not available';
      lastSeenSpan.textContent = result.lastSeen ? new Date(result.lastSeen).toLocaleString() : 'Never';
  });

  // Function to fetch and display device list
  function fetchDevices() {
      chrome.storage.local.get(['serverUrl', 'apiKey'], function(config) {
          fetch(`${config.serverUrl}/devices`, {
              headers: {
                  'X-API-Key': config.apiKey
              }
          })
          .then(response => response.json())
          .then(data => {
              deviceListDiv.innerHTML = '<h3>Devices:</h3>';
              data.devices.forEach(device => {
                  deviceListDiv.innerHTML += `
                      <div class="card mb-2">
                          <div class="card-body">
                              <h5 class="card-title">Device ID: ${device.id}</h5>
                              <p class="card-text">UUID: ${device.uuid}</p>
                              <p class="card-text">Internal IP: ${device.internal_ip}</p>
                              <p class="card-text">Last Seen: ${new Date(device.last_seen).toLocaleString()}</p>
                          </div>
                      </div>
                  `;
              });
          })
          .catch(error => {
              console.error('Error fetching devices:', error);
              deviceListDiv.innerHTML = '<p class="text-danger">Error fetching devices</p>';
          });
      });
  }

  // Fetch devices on popup open
  fetchDevices();

  // Refresh devices when button is clicked
  refreshDevicesButton.addEventListener('click', fetchDevices);
});
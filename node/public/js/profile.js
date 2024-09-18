let devices = [];
let currentPage = 1;
const devicesPerPage = 10;

async function loadUserProfile() {
    console.log('Loading user profile');
    try {
        const token = await auth0Client.getTokenSilently();
        const user = await auth0Client.getUser();

        const response = await fetch(`${apiBaseUrl}/user_info`, {
            headers: {
                Authorization: `Bearer ${token}`
            }
        });

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        const data = await response.json();
        const userInfo = {
            ...user,
            ...data,
            org_id: user['https://watchhousesspm.com/org_id'],
            org_name: user['https://watchhousesspm.com/org_name'],
            roles: user['https://watchhousesspm.com/roles'] || []
        };

        document.getElementById('userPicture').src = userInfo.picture;
        document.getElementById('userNickname').textContent = userInfo.nickname;
        document.getElementById('userEmail').textContent = `Email: ${userInfo.email}`;
        document.getElementById('emailVerified').textContent = `Email verified: ${userInfo.email_verified ? 'Yes' : 'No'}`;
        document.getElementById('orgName').textContent = userInfo.org_name;
        document.getElementById('userRoles').textContent = `Roles: ${userInfo.roles.join(', ')}`;

        // Show the profile content
        document.getElementById('profile-content').style.display = 'block';
        document.getElementById('login-prompt').style.display = 'none';

        setupApiKeyManagement();
        setupDeviceManagement();

    } catch (error) {
        console.error('Error loading user profile:', error);
        // Instead of showing an error message, we'll log it and continue
        console.warn('Failed to load some user profile data. Continuing with available information.');
    }
}

function setupApiKeyManagement() {
    console.log('Setting up API Key Management');
    const createApiKeyBtn = document.getElementById('createApiKey');

    if (createApiKeyBtn) {
        console.log('Create API Key button found');
        createApiKeyBtn.addEventListener('click', createApiKey);
    } else {
        console.log('Create API Key button not found');
    }

    // Automatically list API keys when the profile loads
    listApiKeys();
}

async function createApiKey() {
    console.log('Creating API Key');
    try {
        const token = await auth0Client.getTokenSilently();
        const user = await auth0Client.getUser();
        const orgId = user['https://watchhousesspm.com/org_id'];
        
        const response = await fetch(`${apiBaseUrl}/api-keys`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ org_id: orgId })
        });
        
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        const data = await response.json();
        alert(`New API Key created: ${data.api_key}`);
        listApiKeys();  // Refresh the list after creation
    } catch (error) {
        console.error('Error creating API key:', error);
        showError(`Failed to create API key: ${error.message}`);
    }
}

async function listApiKeys() {
    console.log('Listing API Keys');
    try {
        const token = await auth0Client.getTokenSilently();
        const response = await fetch(`${apiBaseUrl}/api-keys`, {
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });
        
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        const data = await response.json();
        const apiKeyListElement = document.getElementById('apiKeyList');
        apiKeyListElement.innerHTML = '<h4 class="mb-3">Your API Keys:</h4>';
        
        if (data.api_keys.length === 0) {
            apiKeyListElement.innerHTML += '<p class="text-muted">No API keys found. Create one to get started.</p>';
        } else {
            const table = document.createElement('table');
            table.className = 'table table-striped table-hover';
            table.innerHTML = `
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Key</th>
                        <th>Created</th>
                        <th>Last Used</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    ${data.api_keys.map(key => `
                        <tr>
                            <td>${key.id}</td>
                            <td>
                                <div class="input-group">
                                    <input type="text" class="form-control" value="${key.key}" readonly>
                                    <button class="btn btn-outline-secondary" type="button" onclick="copyToClipboard('${key.key}')">Copy</button>
                                </div>
                            </td>
                            <td>${new Date(key.created_at).toLocaleString()}</td>
                            <td>${key.last_used ? new Date(key.last_used).toLocaleString() : 'Never'}</td>
                            <td>
                                <button onclick="deleteApiKey('${key.id}')" class="btn btn-danger btn-sm rounded-pill">Delete</button>
                            </td>
                        </tr>
                    `).join('')}
                </tbody>
            `;
            apiKeyListElement.appendChild(table);
        }
    } catch (error) {
        console.error('Error listing API keys:', error);
        showError(`Failed to list API keys: ${error.message}`);
    }
}

// Add this function to enable copying API keys
function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
        alert('API Key copied to clipboard!');
    }, (err) => {
        console.error('Could not copy text: ', err);
    });
}

// Make the copyToClipboard function globally available
window.copyToClipboard = copyToClipboard;

function setupDeviceManagement() {
    const deviceManagementSection = document.getElementById('deviceManagement');
    deviceManagementSection.innerHTML = `
        <div class="card-body">
            <h3 class="card-title mb-3">Device Management</h3>
            <input type="text" id="deviceSearch" class="form-control mb-3" placeholder="Search devices...">
            <div id="deviceList" class="mt-3"></div>
        </div>
    `;
    
    document.getElementById('deviceSearch').addEventListener('input', () => {
        currentPage = 1;
        updateDeviceTable();
    });
    
    loadDevices();
}

async function loadDevices() {
    try {
        const token = await auth0Client.getTokenSilently();
        const response = await fetch(`${apiBaseUrl}/devices`, {
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });
        
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        const data = await response.json();
        devices = data.devices;
        updateDeviceTable();
    } catch (error) {
        console.error('Error loading devices:', error);
        showError(`Failed to load devices: ${error.message}`);
    }
}

function updateDeviceTable() {
    const searchTerm = document.getElementById('deviceSearch').value.toLowerCase();
    const filteredDevices = devices.filter(device => 
        device.id.toString().includes(searchTerm) ||
        device.uuid.toLowerCase().includes(searchTerm) ||
        (device.internal_ip && device.internal_ip.toLowerCase().includes(searchTerm))
    );

    const startIndex = (currentPage - 1) * devicesPerPage;
    const endIndex = startIndex + devicesPerPage;
    const devicesToShow = filteredDevices.slice(startIndex, endIndex);

    const deviceListElement = document.getElementById('deviceList');
    deviceListElement.innerHTML = '';
    
    if (devicesToShow.length === 0) {
        deviceListElement.innerHTML = '<p>No devices found.</p>';
    } else {
        const table = document.createElement('table');
        table.className = 'table table-striped';
        table.innerHTML = `
            <thead>
                <tr>
                    <th>Device ID</th>
                    <th>UUID</th>
                    <th>Internal IP</th>
                    <th>Last Seen</th>
                    <th>Status</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
                ${devicesToShow.map(device => `
                    <tr>
                        <td>${device.id}</td>
                        <td>${device.uuid}</td>
                        <td>${device.internal_ip || 'N/A'}</td>
                        <td>${new Date(device.last_seen).toLocaleString()}</td>
                        <td>${getStatusBadge(device.last_seen)}</td>
                        <td>
                            <button onclick="deleteDevice('${device.id}')" class="btn btn-danger btn-sm rounded-pill">Delete</button>
                        </td>
                    </tr>
                `).join('')}
            </tbody>
        `;
        deviceListElement.appendChild(table);
    }

    updatePagination(filteredDevices.length);
}

function getStatusBadge(lastSeen) {
    const now = new Date();
    
    // Parse the lastSeen string explicitly as UTC
    const [datePart, timePart] = lastSeen.split('T');
    const [year, month, day] = datePart.split('-');
    const [hours, minutes, seconds] = timePart.split(':');
    const lastSeenDate = new Date(Date.UTC(year, month - 1, day, hours, minutes, parseInt(seconds)));
    
    // Calculate the difference in minutes
    const diffMinutes = (now - lastSeenDate) / (1000 * 60);
    
    console.log('Current time (UTC):', now.toUTCString());
    console.log('Last seen time (UTC):', lastSeenDate.toUTCString());
    console.log('Difference in minutes:', diffMinutes);

    if (diffMinutes <= 5) {
        return '<span class="badge bg-success">Active</span>';
    } else {
        return '<span class="badge bg-warning text-dark">Inactive</span>';
    }
}

function updatePagination(totalDevices) {
    const totalPages = Math.ceil(totalDevices / devicesPerPage);
    const paginationElement = document.createElement('div');
    paginationElement.className = 'd-flex justify-content-between align-items-center mt-3';
    paginationElement.innerHTML = `
        <div>
            Showing ${(currentPage - 1) * devicesPerPage + 1} - ${Math.min(currentPage * devicesPerPage, totalDevices)} of ${totalDevices} devices
        </div>
        <div>
            <button id="prevPage" class="btn btn-secondary rounded-pill" ${currentPage === 1 ? 'disabled' : ''}>&laquo; Previous</button>
            <button id="nextPage" class="btn btn-secondary rounded-pill" ${currentPage === totalPages ? 'disabled' : ''}>Next &raquo;</button>
        </div>
    `;
    document.getElementById('deviceList').appendChild(paginationElement);

    document.getElementById('prevPage').addEventListener('click', () => changePage(-1));
    document.getElementById('nextPage').addEventListener('click', () => changePage(1));
}

function changePage(direction) {
    currentPage += direction;
    updateDeviceTable();
}

async function deleteDevice(deviceId) {
    if (confirm('Are you sure you want to delete this device?')) {
        try {
            const token = await auth0Client.getTokenSilently();
            const response = await fetch(`${apiBaseUrl}/devices/${deviceId}`, {
                method: 'DELETE',
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            });
            
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            
            alert('Device deleted successfully');
            loadDevices();  // Refresh the list after deletion
        } catch (error) {
            console.error('Error deleting device:', error);
            showError(`Failed to delete device: ${error.message}`);
        }
    }
}

function showError(message) {
    console.error('Error:', message);
    const errorDiv = document.createElement('div');
    errorDiv.className = 'alert alert-danger mt-3';
    errorDiv.textContent = message;
    document.querySelector('.container').appendChild(errorDiv);
    setTimeout(() => errorDiv.remove(), 5000);
}

// Make functions globally available
window.createApiKey = createApiKey;
window.listApiKeys = listApiKeys;
window.deleteApiKey = deleteApiKey;
window.deleteDevice = deleteDevice;

// Initialize profile when the script loads
document.addEventListener('DOMContentLoaded', loadUserProfile);
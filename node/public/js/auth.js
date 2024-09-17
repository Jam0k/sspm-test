let auth0Client;
const apiBaseUrl = 'http://127.0.0.1:8000';  // Replace with your actual API base URL

async function initAuth0() {
    console.log('Initializing Auth0');
    try {
        auth0Client = await auth0.createAuth0Client({
            domain: 'dev-mazc2h57lknel3yr.uk.auth0.com',
            clientId: 'ICvvsiC19v8WtUSQI910bSNQNjnWwKMF',
            authorizationParams: {
                redirect_uri: window.location.origin,
                audience: 'sspm',
                scope: 'openid profile email'
            },
            cacheLocation: 'localstorage'
        });

        if (location.search.includes("code=") && location.search.includes("state=")) {
            await auth0Client.handleRedirectCallback();
            window.history.replaceState({}, document.title, "/");
        }

        await updateUI();

        const loginButton = document.getElementById('loginButton');
        const logoutButton = document.getElementById('logoutButton');

        if (loginButton) loginButton.addEventListener('click', login);
        if (logoutButton) logoutButton.addEventListener('click', logout);

        setupApiKeyManagement();

    } catch (error) {
        console.error("Error initializing Auth0:", error);
        showError("Failed to initialize authentication. Please try again later.");
    }
}

async function updateUI() {
    console.log('Updating UI');
    const isAuthenticated = await auth0Client.isAuthenticated();
    console.log('Is authenticated:', isAuthenticated);
    document.getElementById('loginButton').style.display = isAuthenticated ? 'none' : 'inline-block';
    document.getElementById('logoutButton').style.display = isAuthenticated ? 'inline-block' : 'none';

    if (isAuthenticated && window.location.pathname === '/profile') {
        await loadUserProfile();
    }
}

async function login() {
    console.log('Logging in');
    await auth0Client.loginWithRedirect({
        redirect_uri: window.location.origin + '/profile'
    });
}

async function logout() {
    console.log('Logging out');
    await auth0Client.logout({
        logoutParams: {
            returnTo: window.location.origin
        }
    });
}

async function loadUserProfile() {
    console.log('Loading user profile');
    try {
        const token = await auth0Client.getTokenSilently();
        const user = await auth0Client.getUser();

        const response = await fetch('http://localhost:8000/user_info', {
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
        document.getElementById('userRoles').textContent = userInfo.roles.join(', ');

        // Show the profile content
        document.getElementById('profile-content').style.display = 'block';
        document.getElementById('login-prompt').style.display = 'none';

    } catch (error) {
        console.error('Error loading user profile:', error);
        showError('Failed to load user profile. Please try again later.');
    }
}

function setupApiKeyManagement() {
    console.log('Setting up API Key Management');
    const createApiKeyBtn = document.getElementById('createApiKey');
    const listApiKeysBtn = document.getElementById('listApiKeys');

    if (createApiKeyBtn) {
        console.log('Create API Key button found');
        createApiKeyBtn.addEventListener('click', createApiKey);
    } else {
        console.log('Create API Key button not found');
    }

    if (listApiKeysBtn) {
        console.log('List API Keys button found');
        listApiKeysBtn.addEventListener('click', listApiKeys);
    } else {
        console.log('List API Keys button not found');
    }
}

async function createApiKey() {
    console.log('Creating API Key');
    try {
        const token = await auth0Client.getTokenSilently();
        const user = await auth0Client.getUser();
        const orgId = user['https://watchhousesspm.com/org_id'];
        
        const response = await fetch('http://localhost:8000/api-keys', {
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
        const response = await fetch('http://localhost:8000/api-keys', {
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });
        
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        const data = await response.json();
        const apiKeyListElement = document.getElementById('apiKeyList');
        apiKeyListElement.innerHTML = '<h4>Your API Keys:</h4>';
        data.api_keys.forEach(key => {
            const keyElement = document.createElement('div');
            keyElement.innerHTML = `
                <p>ID: ${key.id}</p>
                <p>Key: ${key.key}</p>
                <p>Created: ${new Date(key.created_at).toLocaleString()}</p>
                <p>Last Used: ${key.last_used ? new Date(key.last_used).toLocaleString() : 'Never'}</p>
                <button onclick="deleteApiKey('${key.id}')" class="btn btn-danger btn-sm">Delete</button>
                <hr>
            `;
            apiKeyListElement.appendChild(keyElement);
        });
    } catch (error) {
        console.error('Error listing API keys:', error);
        showError(`Failed to list API keys: ${error.message}`);
    }
}

async function deleteApiKey(keyId) {
    console.log('Deleting API Key:', keyId);
    try {
        const token = await auth0Client.getTokenSilently();
        const response = await fetch(`http://localhost:8000/api-keys/${keyId}`, {
            method: 'DELETE',
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });
        
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        alert('API Key deleted successfully');
        listApiKeys();  // Refresh the list after deletion
    } catch (error) {
        console.error('Error deleting API key:', error);
        showError(`Failed to delete API key: ${error.message}`);
    }
}


async function setupDeviceManagement() {
    const listDevicesBtn = document.getElementById('listDevices');
    if (listDevicesBtn) {
        listDevicesBtn.addEventListener('click', listDevices);
    }
}

async function listDevices() {
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
        const deviceListElement = document.getElementById('deviceList');
        deviceListElement.innerHTML = '<h4>Your Devices:</h4>';
        data.devices.forEach(device => {
            const deviceElement = document.createElement('div');
            deviceElement.className = 'card mb-2';
            deviceElement.innerHTML = `
                <div class="card-body">
                    <h5 class="card-title">Device ID: ${device.id}</h5>
                    <p class="card-text">UUID: ${device.uuid}</p>
                    <p class="card-text">Internal IP: ${device.internal_ip || 'N/A'}</p>
                    <p class="card-text">Last Seen: ${new Date(device.last_seen).toLocaleString()}</p>
                </div>
            `;
            deviceListElement.appendChild(deviceElement);
        });
    } catch (error) {
        console.error('Error listing devices:', error);
        showError(`Failed to list devices: ${error.message}`);
    }
}

// Update the existing updateUI function to include setupDeviceManagement
async function updateUI() {
    const isAuthenticated = await auth0Client.isAuthenticated();
    document.getElementById('loginButton').style.display = isAuthenticated ? 'none' : 'inline-block';
    document.getElementById('logoutButton').style.display = isAuthenticated ? 'inline-block' : 'none';

    if (isAuthenticated && window.location.pathname === '/profile') {
        await loadUserProfile();
        setupApiKeyManagement();
        setupDeviceManagement();
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

// Initialize Auth0 when the script loads
document.addEventListener('DOMContentLoaded', initAuth0);

// Make auth0Client and API key functions globally available
window.auth0Client = auth0Client;
window.createApiKey = createApiKey;
window.listApiKeys = listApiKeys;
window.deleteApiKey = deleteApiKey;
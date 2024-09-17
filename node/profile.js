let auth0Client;

document.addEventListener('DOMContentLoaded', async () => {
    async function initializeAuth0() {
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
            window.history.replaceState({}, document.title, window.location.pathname);
        }
    }

    async function loadUserProfile() {
        try {
            await initializeAuth0();
            const isAuthenticated = await auth0Client.isAuthenticated();

            if (!isAuthenticated) {
                window.location.href = 'index.html';
                return;
            }

            const token = await auth0Client.getTokenSilently();
            const user = await auth0Client.getUser();

            // Call the backend API to get additional user info
            const response = await fetch(`${apiBaseUrl}/user_info`, {
                headers: {
                    Authorization: `Bearer ${token}`
                }
            });

            if (!response.ok) {
                throw new Error('Failed to fetch user info');
            }

            const data = await response.json();

            // Combine Auth0 user info with backend data
            const userInfo = {
                ...user,
                ...data,
                org_id: user['https://watchhousesspm.com/org_id'],
                org_name: user['https://watchhousesspm.com/org_name'],
                roles: user['https://watchhousesspm.com/roles'] || []
            };

            // Update the DOM with user information
            document.getElementById('userPicture').src = userInfo.picture;
            document.getElementById('userNickname').textContent = userInfo.nickname;
            document.getElementById('userEmail').textContent = userInfo.email;
            document.getElementById('emailVerified').textContent = `Email verified: ${userInfo.email_verified ? 'Yes' : 'No'}`;
            document.getElementById('orgName').textContent = userInfo.org_name;
            document.getElementById('userRoles').textContent = userInfo.roles.join(', ');

            // Update UI based on user roles
            const apiKeyManagement = document.getElementById('apiKeyManagement');
            if (apiKeyManagement) {
                apiKeyManagement.style.display = userInfo.roles.includes('Admin') ? 'block' : 'none';
            }
        } catch (error) {
            console.error('Error loading user profile:', error);
            showError('Failed to load user profile. Please try again later.');
        }
    }

    // Load user profile when the page loads
    await loadUserProfile();
});

function showError(message) {
    const errorDiv = document.createElement('div');
    errorDiv.className = 'alert alert-danger mt-3';
    errorDiv.textContent = message;
    document.querySelector('.container').appendChild(errorDiv);
    setTimeout(() => errorDiv.remove(), 5000);
}

// Make sure apiBaseUrl is defined
const apiBaseUrl = 'http://127.0.0.1:8000';
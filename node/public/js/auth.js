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

    } catch (error) {
        console.error("Error initializing Auth0:", error);
        showError("Failed to initialize authentication. Please try again later.");
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
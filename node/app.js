let auth0Client;
const apiBaseUrl = 'http://127.0.0.1:8000';

window.onload = async () => {
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
    } catch (error) {
        console.error("Error initializing Auth0:", error);
        showError("Failed to initialize authentication. Please try again later.");
    }
};

async function updateUI() {
    const isAuthenticated = await auth0Client.isAuthenticated();
    document.querySelectorAll('.auth-dependent').forEach(el => {
        el.style.display = isAuthenticated ? 'block' : 'none';
    });
    document.querySelectorAll('.no-auth-dependent').forEach(el => {
        el.style.display = isAuthenticated ? 'none' : 'block';
    });

    if (isAuthenticated) {
        const user = await auth0Client.getUser();
        const userNameElement = document.getElementById('user-name');
        if (userNameElement) {
            userNameElement.textContent = user.name;
        }
    }
}

async function login() {
    await auth0Client.loginWithRedirect({
        redirect_uri: window.location.origin + '/dashboard.html'
    });
}

async function logout() {
    await auth0Client.logout({
        logoutParams: {
            returnTo: window.location.origin
        }
    });
}

function showError(message) {
    const errorDiv = document.createElement('div');
    errorDiv.className = 'alert alert-danger mt-3';
    errorDiv.textContent = message;
    document.querySelector('.container').appendChild(errorDiv);
    setTimeout(() => errorDiv.remove(), 5000);
}

// Add event listeners
document.addEventListener('DOMContentLoaded', () => {
    const loginButton = document.getElementById('loginButton');
    const logoutButton = document.getElementById('logoutButton');

    if (loginButton) loginButton.addEventListener('click', login);
    if (logoutButton) logoutButton.addEventListener('click', logout);
});
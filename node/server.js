const express = require('express');
const expressLayouts = require('express-ejs-layouts');
const path = require('path');
const app = express();
const port = 5500;

// Set up EJS as the templating engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Set up express-ejs-layouts
app.use(expressLayouts);
app.set('layout', 'layout');

// Serve static files from the 'public' directory
app.use(express.static(path.join(__dirname, 'public')));

// Serve Auth0 spa-js from node_modules
app.use('/auth0', express.static(path.join(__dirname, 'node_modules/@auth0/auth0-spa-js/dist')));

// Route for the home page
app.get('/', (req, res) => {
    res.render('index', { title: 'SSPM Home' });
});

// Route for the profile page
app.get('/profile', (req, res) => {
    res.render('profile', { title: 'User Profile' });
});

// Start the server
app.listen(port, () => {
    console.log(`Frontend server listening at http://localhost:${port}`);
});
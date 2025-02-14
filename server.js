// const express = require('express');
// const cors = require('cors');
// const fetch = require('node-fetch');
// const app = express();
// const path = require('path');
// // const fs = require('fs');

// app.use(cors());
// app.use(express.json());

// app.use(express.static(path.join(__dirname, 'public')));

// // Serve your HTML file
// app.get('/', (req, res) => {
//     res.sendFile(path.join(__dirname, 'public', 'index.html'));
// });

// // const COMPANY_ID = '2422107b-7011-48bb-8366-735e927271f2';
// // const API_KEY = '67325a24e28d69f37f5c49a66cfe4771d5ad368e0a7641c20b099418f69fcc28bfaf7bd2e0d2c0ef5f0eb42e722efd2354b2b4d6ef67c1f5426dc39ba3af8180b5e8ef2007e596822ce0d31a037baa0b674c7468e7a1ed7628cfdfecb8ecce5db58597dbab62944c0f431ef8fe94797f9968f0980678bd610973d25df2e34c13';
// // const REGION = 'com'; // e.g., 'com' for North America

// // // const davinci = fs.readFileSync('public/js/davinci.js','utf8');
// // // eval(davinci);


// // app.get('/get-sdk-token', async (req, res) => {
  
// //   try {
// //     const url = `https://orchestrate-api.pingone.${REGION}/v1/company/${COMPANY_ID}/sdktoken`;
// //     const response = await fetch(url, {
// //       headers: { 'X-SK-API-KEY': API_KEY, },
// //     });

// //     if(!response.ok){
// //         throw new Error(`Pingone API error : ${response.statusText}`);
// //     }
// //     const data = await response.json();
// //     res.json(data);
// //   } catch (error) {
// //     console.error('Error fetching SDK token:', error);
// //     res.status(500).json({error: 'Failed to retrieve SDK token'});
// //   }
// // });


// // const PORT = process.env.PORT || 3000;
// app.listen(3000, () => {
//   console.log('Server running on http://localhost:3000');
// });



//  Copyright © 2019 Ping Identity. All rights reserved.
//
//  This software may be modified and distributed under the terms
//  of the MIT license. See the LICENSE file for details.
//
const http = require('http');
const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');
const session = require('express-session');
const path = require('path');
const fetch = require('node-fetch');
require('dotenv').config();
const cors = require('cors');

const randomString = require("randomstring");

const { createHash } = require('crypto');

const app = express();

app.use(express.json());
app.use(express.static('public'));
app.use(session({
    secret: 'ping one',
    resave: false,
    saveUninitialized: true,
    cookie: { maxAge: 60000 }
}));
app.use(cors());
app.use(express.static(path.join(__dirname, 'public')));
app.set('view engine', 'ejs');


app.use('/pingone', createProxyMiddleware({
    target: 'https://auth.pingone.com',
    changeOrigin: true,
    pathRewrite: {
      '^/pingone': ''
    },
    onProxyReq: (proxyReq, req) => {
      if (req.headers['x-sk-api-key']) {
        proxyReq.setHeader('X-SK-API-KEY', req.headers['x-sk-api-key']);
      }
    },
    onProxyRes: (proxyRes) => {
      proxyRes.headers['access-control-allow-origin'] = '*';
      proxyRes.headers['access-control-allow-methods'] = '*';
      proxyRes.headers['access-control-allow-headers'] = '*';
    }
  }));
  
// Express endpoint to redirect to the login path for PingOne
app.get('/login', async (req, res) => {
    // Generate a unique code_verifier for this session
    const code_verifier = randomString.generate(128);
    req.session.code_verifier = code_verifier;

    // Create the authorization url expected by PingOne
    authorizationRequest = new URL(process.env.PINGONE_AUTH_ENDPOINT);
    authorizationRequest.searchParams.append('redirect_uri', process.env.REDIRECT_URI);
    authorizationRequest.searchParams.append('client_id', process.env.PINGONE_CLIENT_ID);
    authorizationRequest.searchParams.append('scope', process.env.PINGONE_SCOPES);
    authorizationRequest.searchParams.append('response_type', 'code');
    const code_challenge = createHash('sha256').update(code_verifier).digest('base64url');
    authorizationRequest.searchParams.append('code_challenge', code_challenge);
    authorizationRequest.searchParams.append('code_challenge_method', 'S256');

    // Redirect to the PingOne authorization url for your environment to begin the authentication process
    res.redirect(authorizationRequest.toString());
});

// Extract the callback path if the redirect uri is present, otherwise use /callback
const redirectUri = process.env.REDIRECT_URI;
const match = redirectUri.match(/:\d+(\/.*)/);
const callbackPath = match ? match[1] : "/callback";

// Express endpoint serving as the REDIRECT_URI for PingOne
// Expecting query parameter of `code`
app.get(callbackPath, async (req, res) => {
    const authorizationCode = req.query?.code;

    // Check for the authorization code
    if (!authorizationCode) {
        res.status(404).send('Authorization code not found:' + req.url);
    }

    // Retrieve the code_verifier from the session
    const code_verifier = req.session.code_verifier;
    if (!code_verifier) {
        return res.status(400).send('Code verifier not found in session');
    }

    // The authorization code flow requires auth code based on the user credentials and
    // the base64 encoded client credentials assigned to the application created in PingOne
    const url = process.env.PINGONE_TOKEN_ENDPOINT;
    const clientCredentials = process.env.PINGONE_CLIENT_ID + ':' + process.env.PINGONE_CLIENT_SECRET;
    const authorizationHeader = 'Basic ' + Buffer.from(clientCredentials).toString('base64');

    // URLSearchParams is used as the Content-Type is application/x-www-form-urlencoded
    const body = new URLSearchParams();
    body.append('grant_type', 'authorization_code');
    body.append('code', authorizationCode);
    body.append('redirect_uri', process.env.REDIRECT_URI);
    body.append('code_verifier', code_verifier);

    // Back channel call to PingOne for the user access token
    try {
        const response = await fetch(url, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Authorization': authorizationHeader
            },
            body
        });

        if (response.ok) {
            // Authentication Successful
            const result = await response.json();

            // Update the success action for your app's implementation here
            // Save tokens to session data
            req.session.data = {
                accessToken: result.access_token,
                idToken: result.id_token
            }

            // Redirect to the user dashboard
            res.redirect('/dashboard');
        } else {
            // Unexpected response
            res.status(response.status).send(response.json());
        }
    } catch (error) {
        // Error response
        console.log(error);
        res.status(500).send(error);
    }
});

// End the app session as well as the PingOne session
app.get('/logout', async function(req, res){
    req.session.destroy();
    res.redirect(process.env.PINGONE_SIGNOFF_ENDPOINT);
});

// Website dashboard page
app.get('/dashboard', function(req, res){
    // Re-authenticate if no session is found
    if (!req.session.data) {
        return res.redirect('login');
    }

    // Session exists so render dashboard
    res.render('dashboard', {
        accessToken: req.session.data.accessToken,
        idToken: req.session.data.idToken
    });
});

// Website default page
app.get('/', function(req,res){
    res.sendFile(path.join(__dirname + '/public/index.html'));
});

const server = http.createServer(app);
const port = 3000;
server.listen(port);
console.debug('Server listening on port ' + port);
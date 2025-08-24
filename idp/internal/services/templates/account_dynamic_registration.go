// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package templates

import (
	"bytes"
	"errors"
	"fmt"
	"html/template"

	"github.com/tugascript/devlogs/idp/internal/controllers/paths"
	"github.com/tugascript/devlogs/idp/internal/providers/database"
	"github.com/tugascript/devlogs/idp/internal/services/dtos"
)

const accountDynamicRegistrationBaseTemplate = `
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body {
            display: flex;
            justify-content: center;
            align-items: center;
            font-family: 'Roboto', sans-serif;
            height: 100vh;
            width: 100vw;
            margin: 0;
            padding: 0;
            background-color: #424242;
        }

        #page-content {
            margin: 0 1em;
            background-color: #f5f5f5;
            border-radius: 1em;
            padding: 1em;
        }

        #title-container {
            display: flex;
            flex-direction: column;
            align-items: center;
        }

        #title-container h1 {
            font-size: 2.2rem;
            font-weight: 700;
            margin-bottom: 0.5em;
            text-align: center;
            color: #222;
            letter-spacing: 1px;
        }

        #logo-container {
            display: flex;
            justify-content: center;
            align-items: center;
        }

        #logo {
            width: 10vw;
            height: 10vw;
        }

        /* For large screens (desktop) */
        @media (max-width: 1200px) {
            #logo {
                width: 20vw;
                height: 20vw;
            }
        }

        /* For small screens (mobile) */
        @media (max-width: 900px) {
            #logo {
                width: 35vw;
                height: 35vw;
            }
        }

        /* For very small screens */
        @media (max-width: 600px) {
            #logo {
                width: 50vw;
                height: 50vw;
            }
        }


        form {
            display: flex;
            flex-direction: column;
            gap: 0.75rem;
        }

        input {
            padding: 10px;
            border: 1px solid #ccc;
            border-radius: 0.75rem;
            font-size: 1.1rem;
            color: #000;
            outline: none;
            background-color: #FAFAFA;
        }

        button {
            padding: 10px;
            border: 1px solid #000;
            background-color: #000;
            color: #fff;
            font-size: 1rem;
            cursor: pointer;
            border-radius: 1em;
            padding: 12px 16px;
        }

        button:hover {
            background-color: #333;
        }

        .oauth-buttons {
            display: flex;
            flex-direction: column;
            gap: 0.75rem;
            margin-top: 1rem;
        }

        .oauth-button {
            display: flex;
            align-items: center;
            justify-content: flex-start;
            gap: 0.75rem;
            padding: 12px 16px;
            border: 1px solid #e0e0e0;
            border-radius: 1em;
            background-color: #FAFAFA;
            color: #333;
            font-size: 1rem;
            cursor: pointer;
            transition: all 0.2s ease;
            min-height: 48px;
        }

        .oauth-button-content {
            display: flex;
            align-items: center;
            gap: 0.75rem;
            position: relative;
            width: 100%;
        }

        .oauth-button-text {
            font-size: 1rem;
            text-align: center;
            margin-left: -1em;
            flex: 1;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }

        .oauth-button:hover {
            background-color: #f5f5f5;
            border-color: #ccc;
        }

        .oauth-button.apple {
            background-color: #000;
            color: #fff;
            border-color: #000;
        }

        .oauth-button.apple:hover {
            background-color: #333;
        }

        .oauth-button.google {
            background-color: #FAFAFA;
            color: #333;
            border-color: #dadce0;
        }

        .oauth-button.google:hover {
            background-color: #f8f9fa;
            border-color: #c6c8ca;
        }

        .oauth-button.github {
            background-color: #24292e;
            color: #fff;
            border-color: #24292e;
        }

        .oauth-button.github:hover {
            background-color: #2f363d;
        }

        .oauth-button.facebook {
            background-color: #1877f2;
            color: #fff;
            border-color: #1877f2;
        }

        .oauth-button.facebook:hover {
            background-color: #166fe5;
        }

        .oauth-button.microsoft {
            background-color: #FAFAFA;
            color: #333;
            border-color: #dadce0;
        }

        .oauth-button.microsoft:hover {
            background-color: #f8f9fa;
            border-color: #c6c8ca;
        }

        .oauth-icon {
            width: 20px;
            height: 20px;
            flex-shrink: 0;
            padding-left: 0.5em;
        }

        .divider {
            display: flex;
            align-items: center;
            margin: 1rem 0;
            color: #666;
            font-size: 0.9rem;
        }

        .divider::before,
        .divider::after {
            content: '';
            flex: 1;
            height: 1px;
            background-color: #e0e0e0;
        }

        .divider span {
            padding: 0 1rem;
        }

        h1 {
            font-size: 2.2rem;
            font-weight: 700;
            margin-bottom: 0.5em;
            text-align: center;
            color: #222;
            letter-spacing: 1px;
        }
    </style>
    <title>OAuth2.0 Dynamic Registration Authorization</title>
</head>

<body>
    <div id="page-content">
        <div id="title-container">
            <div id="logo-container">
                <svg id="logo" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128" fill="none">
                    <rect width="95" height="60" x="16.5" y="15.5" stroke="#000" stroke-width="5" rx="7.5" />
                    <path fill="#000"
                        d="M51.5 66.833c-1.146 0-2.127-.408-2.943-1.224-.816-.816-1.224-1.796-1.224-2.942V41.833c0-1.145.408-2.126 1.224-2.942.816-.816 1.797-1.224 2.943-1.224h2.083V33.5c0-2.882 1.016-5.338 3.047-7.37 2.031-2.031 4.488-3.047 7.37-3.047 2.882 0 5.338 1.016 7.37 3.047 2.031 2.032 3.047 4.488 3.047 7.37v4.167H76.5c1.146 0 2.127.408 2.943 1.224.816.816 1.224 1.797 1.224 2.942v20.834c0 1.145-.408 2.126-1.224 2.942-.816.816-1.797 1.224-2.943 1.224h-25Zm0-4.166h25V41.833h-25v20.834Zm12.5-6.25c1.146 0 2.127-.408 2.943-1.224.816-.816 1.224-1.797 1.224-2.943 0-1.146-.408-2.127-1.224-2.943-.816-.816-1.797-1.224-2.943-1.224-1.146 0-2.127.408-2.943 1.224-.816.816-1.224 1.797-1.224 2.943 0 1.146.408 2.127 1.224 2.943.816.816 1.797 1.224 2.943 1.224Zm-6.25-18.75h12.5V33.5c0-1.736-.608-3.212-1.823-4.427-1.215-1.215-2.69-1.823-4.427-1.823-1.736 0-3.212.608-4.427 1.823-1.215 1.215-1.823 2.69-1.823 4.427v4.167Z" />
                    <path stroke="#000" stroke-width="5"
                        d="m10.834 99.94 5.866-10A10 10 0 0 1 25.325 85h77.35c3.548 0 6.83 1.88 8.625 4.94l5.866 10c3.911 6.667-.897 15.06-8.625 15.06H19.459c-7.728 0-12.536-8.393-8.625-15.06Z" />
                    <path fill="#000"
                        d="M31.344 106V94.625h2.945c.526 0 1.018.065 1.477.195.458.125.875.305 1.25.54.328.192.62.43.875.71.26.276.487.578.68.907.223.4.395.843.515 1.328.125.484.187 1 .187 1.547v.937c0 .526-.057 1.023-.171 1.492a5.491 5.491 0 0 1-.485 1.289c-.198.349-.43.672-.695.969a4.113 4.113 0 0 1-.875.734c-.37.235-.779.415-1.227.539a5.174 5.174 0 0 1-1.422.188h-3.054Zm2.21-9.594v7.828h.844c.271 0 .524-.033.758-.101.235-.068.448-.167.64-.297a2.24 2.24 0 0 0 .532-.516c.162-.213.3-.461.414-.742.094-.245.164-.516.211-.812.052-.302.078-.628.078-.977v-.953c0-.328-.026-.638-.078-.93a4.028 4.028 0 0 0-.21-.812 2.897 2.897 0 0 0-.454-.781 2.351 2.351 0 0 0-.64-.563 2.376 2.376 0 0 0-.626-.25 2.725 2.725 0 0 0-.734-.094h-.734ZM48 101.016h-4.672v3.211h5.461V106h-7.664V94.625h7.64v1.79h-5.437v2.866H48v1.735ZM53.266 106l-3.438-11.375h2.422l1.93 7.43.195.765.21-.773 1.938-7.422h2.422L55.5 106h-2.234Zm18.914-1.773h5.328V106h-7.531V94.625h2.203v9.602Zm15.195-3.079c0 .49-.044.956-.133 1.399a5.867 5.867 0 0 1-.383 1.219 4.827 4.827 0 0 1-.656 1.031c-.26.312-.557.573-.89.781a3.915 3.915 0 0 1-1 .422c-.36.104-.748.156-1.165.156-.442 0-.851-.057-1.226-.172a3.771 3.771 0 0 1-1.024-.484 4.03 4.03 0 0 1-.812-.789 4.635 4.635 0 0 1-.602-1.055 6.022 6.022 0 0 1-.336-1.172 7.84 7.84 0 0 1-.109-1.336v-1.656c0-.5.042-.974.125-1.422.089-.448.216-.862.383-1.242.161-.36.357-.685.586-.976a3.53 3.53 0 0 1 1.805-1.219c.37-.11.77-.164 1.203-.164.437 0 .846.057 1.226.172.386.109.732.268 1.04.476.306.198.575.438.804.719.234.281.435.591.602.93.182.385.32.807.414 1.265.099.459.148.946.148 1.461v1.656Zm-2.227-1.671a6.97 6.97 0 0 0-.046-.829 4.305 4.305 0 0 0-.133-.734 3.06 3.06 0 0 0-.313-.75 1.917 1.917 0 0 0-.46-.547c-.141-.104-.3-.185-.477-.242a1.822 1.822 0 0 0-.578-.086c-.204 0-.388.026-.555.078a1.455 1.455 0 0 0-.438.227 1.957 1.957 0 0 0-.453.547c-.12.218-.213.474-.28.765a5.7 5.7 0 0 0-.118.735c-.021.265-.031.544-.031.836v1.671c0 .276.01.542.03.797.022.256.058.493.11.711.057.276.14.529.25.758.115.224.248.406.399.547.14.125.3.221.476.289.182.068.388.102.617.102.22 0 .42-.032.602-.094.182-.063.344-.154.484-.274.178-.145.326-.328.446-.546.125-.224.224-.477.297-.758.057-.219.099-.459.125-.719.03-.26.046-.531.046-.813v-1.671Zm11.72 5.195c-.141.172-.334.346-.579.523a4.406 4.406 0 0 1-.867.477 5.98 5.98 0 0 1-1.133.351 6.43 6.43 0 0 1-1.344.133c-.416 0-.81-.049-1.18-.148a3.854 3.854 0 0 1-1.007-.414 3.995 3.995 0 0 1-.828-.688 4.036 4.036 0 0 1-.625-.929 5.285 5.285 0 0 1-.453-1.305 7.885 7.885 0 0 1-.149-1.578v-1.547c0-.542.05-1.044.149-1.508a5.62 5.62 0 0 1 .421-1.273c.172-.339.37-.644.594-.914.23-.271.48-.506.75-.704a3.637 3.637 0 0 1 1.04-.507c.374-.115.77-.172 1.187-.172.64 0 1.198.08 1.672.242.479.161.882.393 1.21.695.329.307.584.68.766 1.117.188.438.31.93.367 1.477h-2.14a3.466 3.466 0 0 0-.172-.734 1.55 1.55 0 0 0-.305-.54 1.315 1.315 0 0 0-.555-.359 2.22 2.22 0 0 0-.789-.125 1.52 1.52 0 0 0-.484.078 1.588 1.588 0 0 0-.437.227 2.185 2.185 0 0 0-.485.531 3.22 3.22 0 0 0-.351.774c-.073.229-.13.484-.172.765a7.12 7.12 0 0 0-.055.914v1.563c0 .411.026.786.078 1.125.057.338.136.638.235.898.062.151.132.292.21.422.084.125.175.237.274.336.167.167.36.294.578.383.224.083.477.127.758.133a3.29 3.29 0 0 0 .976-.149c.146-.047.274-.099.383-.156a.921.921 0 0 0 .258-.195l.008-2.063h-1.883v-1.64h4.07l.008 4.484Z" />
                </svg>
            </div>
            <h1>{{.Header}}</h1>
        </div>
        %s
    </div>
    <script>
        // PKCE (Proof Key for Code Exchange) implementation
        // Based on RFC 7636: https://tools.ietf.org/html/rfc7636

        // Generate a random string for code verifier
        function generateCodeVerifier() {
            const array = new Uint8Array(32);
            crypto.getRandomValues(array);
            return base64URLEncode(array);
        }

        // Generate code challenge from code verifier using SHA256
        async function generateCodeChallenge(codeVerifier) {
            const encoder = new TextEncoder();
            const data = encoder.encode(codeVerifier);
            const digest = await crypto.subtle.digest('SHA-256', data);
            return base64URLEncode(new Uint8Array(digest));
        }

        // Generate random state parameter
        function generateState() {
            const array = new Uint8Array(16);
            crypto.getRandomValues(array);
            return hexEncode(array);
        }

        // Base64URL encoding (RFC 4648)
        function base64URLEncode(buffer) {
            const base64 = btoa(String.fromCharCode(...buffer));
            return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
        }

        // Hex encoding
        function hexEncode(buffer) {
            return Array.from(buffer, byte => byte.toString(16).padStart(2, '0')).join('');
        }

        // Store PKCE parameters in sessionStorage for later use
        function storePKCEParams(provider, codeVerifier, state) {
            sessionStorage.setItem(provider + "_code_verifier", codeVerifier);
            sessionStorage.setItem(provider + "_state", state);
        }

        // Main OAuth initiation function
        async function initiateOAuth(urlPath) {
            try {
                // Generate PKCE parameters
                const data = urlPath.split('?client_id=');
                const provider = data[1];
                const codeVerifier = generateCodeVerifier();
                const codeChallenge = await generateCodeChallenge(codeVerifier);
                const state = generateState();

                // Store parameters for later verification
                storePKCEParams(provider, codeVerifier, state);

                // Build OAuth URL with PKCE parameters
                const oauthUrl = buildOAuthURL(data[0], provider, codeChallenge, state);

                // Redirect to OAuth provider
                window.location.href = oauthUrl;
            } catch (error) {
                console.error('Failed to initiate OAuth:', error);
                alert('Failed to initiate OAuth. Please try again.');
            }
        }

        // Build OAuth URL with required parameters
        function buildOAuthURL(baseUrl, provider, codeChallenge, state) {
            const params = new URLSearchParams({
                client_id: provider,
                response_type: 'code',
                code_challenge: codeChallenge,
                code_challenge_method: 'S256',
                state: state
            });

            return baseUrl + "?" + params.toString();
        }
    </script>
</body>

</html>
`

func buildEntryAccountDynamicRegistrationTemplate(body string) string {
	return fmt.Sprintf(accountDynamicRegistrationBaseTemplate, body)
}

const baseAccountDynamicRegistrationLoginTitle = "Account Credentials Dynamic Registration"

const loginForm = `
<form action="{{.LoginURL}}" method="post">
    <input type="email" name="email" placeholder="Email">
    <input type="password" name="password" placeholder="Password">
    <button type="submit">Continue</button>
</form>
`

const divider = `
<div class="divider">
    <span>OR</span>
</div>
`

const appleLoginButton = `
<button type="button" class="oauth-button apple" onclick="initiateOAuth('{{.AppleLoginURL}}')">
     <div class="oauth-button-content">
        <svg class="oauth-icon" viewBox="0 0 24 24" fill="currentColor">
            <path
                d="M18.71 19.5c-.83 1.24-1.71 2.45-3.05 2.47-1.34.03-1.77-.79-3.29-.79-1.53 0-2 .77-3.27.82-1.31.05-2.3-1.32-3.14-2.53C4.25 17 2.94 12.45 4.7 9.39c.87-1.52 2.43-2.48 4.12-2.51 1.28-.02 2.5.87 3.29.87.78 0 2.26-1.07 3.81-.91.65.03 2.47.26 3.64 1.98-.09.06-2.17 1.28-2.15 3.81.03 3.02 2.65 4.03 2.68 4.04-.03.07-.42 1.44-1.38 2.83M13 3.5c.73-.83 1.94-1.46 2.94-1.5.13 1.17-.34 2.35-1.04 3.19-.69.85-1.83 1.51-2.95 1.42-.15-1.15.41-2.35 1.05-3.11z" />
        </svg>
        <div class="oauth-button-text">
         	Continue with Apple
        </div>
    </div>
</button>
`

const facebookLoginButton = `
<button type="button" class="oauth-button facebook" onclick="initiateOAuth('{{.FacebookLoginURL}}')">
    <div class="oauth-button-content">
        <svg class="oauth-icon" viewBox="0 0 24 24" fill="currentColor">
            <path
                d="M24 12.073c0-6.627-5.373-12-12-12s-12 5.373-12 12c0 5.99 4.388 10.954 10.125 11.854v-8.385H7.078v-3.47h3.047V9.43c0-3.007 1.792-4.669 4.533-4.669 1.312 0 2.686.235 2.686.235v2.953H15.83c-1.491 0-1.956.925-1.956 1.874v2.25h3.328l-.532 3.47h-2.796v8.385C19.612 23.027 24 18.062 24 12.073z" />
        </svg>
        <div class="oauth-button-text">
         	Continue with Facebook
        </div>
    </div>
</button>
`

const githubLoginButton = `
<button type="button" class="oauth-button github" onclick="initiateOAuth('{{.GithubLoginURL}}')">
    <div class="oauth-button-content">
        <svg class="oauth-icon" viewBox="0 0 24 24" fill="currentColor">
            <path
                d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z" />
        </svg>
        <div class="oauth-button-text">
         	Continue with GitHub
        </div>
    </div>
</button>
`

const googleLoginButton = `
<button type="button" class="oauth-button google" onclick="initiateOAuth('{{.GoogleLoginURL}}')">
    <div class="oauth-button-content">
        <svg class="oauth-icon" viewBox="0 0 24 24">
            <path fill="#4285F4"
                d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" />
            <path fill="#34A853"
                d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" />
            <path fill="#FBBC05"
                d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" />
            <path fill="#EA4335"
                d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" />
        </svg>
        <div class="oauth-button-text">
         	Continue with Google
        </div>
    </div>
</button>
`

const microsoftLoginButton = `
<button type="button" class="oauth-button microsoft" onclick="initiateOAuth('{{.MicrosoftLoginURL}}')">
    <div class="oauth-button-content">
        <svg viewBox="0 0 276 276" xmlns="http://www.w3.org/2000/svg" class="oauth-icon"
            preserveAspectRatio="xMidYMid">
            <rect x="0" y="0" width="122" height="122" fill="#F1511B" />
            <rect x="134" y="0" width="122" height="122" fill="#80CC28" />
            <rect x="0" y="134" width="122" height="122" fill="#00ADEF" />
            <rect x="134" y="134" width="122" height="122" fill="#FBBC09" />
        </svg>
        <div class="oauth-button-text">
        	Continue with Microsoft
        </div>
    </div>
</button>
`

const accountDynamicRegistrationLoginTemplateName = "login"

type accountDynamicRegistrationLoginTemplateData struct {
	Title             string
	Header            string
	LoginURL          string
	AppleLoginURL     string
	FacebookLoginURL  string
	GithubLoginURL    string
	GoogleLoginURL    string
	MicrosoftLoginURL string
}

func BuildAccountDynamicRegistrationLoginTemplate(
	clientID string,
	account *dtos.AccountDTO,
	authProviders []dtos.AuthProviderDTO,
) (string, error) {
	if len(authProviders) == 0 {
		return "", errors.New("no auth providers found")
	}

	baseURL := paths.AccountsBase + paths.CredentialsBase + "/" + clientID + paths.OAuthBase
	data := accountDynamicRegistrationLoginTemplateData{
		Title:  fmt.Sprintf("%s %s", baseAccountDynamicRegistrationLoginTitle, account.GivenName),
		Header: fmt.Sprintf("Confirm Account Credentials Client Registration %s", account.GivenName),
	}
	baseTemplateBody := ""
	for _, provider := range authProviders {
		switch provider.Provider {
		case database.AuthProviderLocal:
			data.LoginURL = baseURL + paths.AuthLogin
			if len(baseTemplateBody) == 0 {
				baseTemplateBody += loginForm
				continue
			}

			baseTemplateBody = loginForm + divider + baseTemplateBody
		case database.AuthProviderApple:
			data.AppleLoginURL = baseURL + paths.OAuthAuth + "?client_id=apple&response_type=code"
			baseTemplateBody += appleLoginButton
		case database.AuthProviderFacebook:
			data.FacebookLoginURL = baseURL + paths.OAuthAuth + "?client_id=facebook&response_type=code"
			baseTemplateBody += facebookLoginButton
		case database.AuthProviderGithub:
			data.GithubLoginURL = baseURL + paths.OAuthAuth + "?client_id=github&response_type=code"
			baseTemplateBody += githubLoginButton
		case database.AuthProviderGoogle:
			data.GoogleLoginURL = baseURL + paths.OAuthAuth + "?client_id=google&response_type=code"
			baseTemplateBody += googleLoginButton
		case database.AuthProviderMicrosoft:
			data.MicrosoftLoginURL = baseURL + paths.OAuthAuth + "?client_id=microsoft"
			baseTemplateBody += microsoftLoginButton
		default:
			return "", fmt.Errorf("unsupported auth provider: %s", provider.Provider)
		}
	}

	loginTemplate := buildEntryAccountDynamicRegistrationTemplate(baseTemplateBody)
	t, err := template.New(accountDynamicRegistrationLoginTemplateName).Parse(loginTemplate)
	if err != nil {
		return "", nil
	}
	var loginTemplateContent bytes.Buffer
	if err := t.Execute(&loginTemplateContent, data); err != nil {
		return "", err
	}

	return loginTemplateContent.String(), nil
}

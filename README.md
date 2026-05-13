# OIDCLite

A lightweight Swift package for OpenID Connect (OIDC) authentication on macOS and iOS. Built for apps that need to authenticate a user and acquire a token set without pulling in a full-featured identity SDK.

OIDCLite implements the Authorization Code flow with PKCE (S256) via `ASWebAuthenticationSession` or `WKWebView`. It also supports the Resource Owner Password Grant (ROPG) for first-party use cases.

**Platforms:** macOS 10.15+, iOS 14+  
**Tested with:** Okta, Microsoft Entra ID (Azure AD), OneLogin, ORY Hydra

---

## Features

- Authorization Code + PKCE (S256 — always enforced, not configurable)
- Async/await API (`macOS 12+` / `iOS 15+`) and callback-based API for earlier targets
- `ASWebAuthenticationSession` and `WKNavigationDelegate` (WKWebView) support
- State parameter for CSRF protection — new random value per request, validated and consumed on redirect
- Nonce for ID token replay protection — new random value per request, validated and cleared after token delivery
- ID token claim validation: `exp`, `aud` (string or array), `iss`, `nonce`
- HTTP Basic client authentication for token requests (RFC 6749 §2.3.1)
- Resource Owner Password Grant (ROPG) with optional override-error routing
- Ephemeral `URLSession` — no shared cookies, cache, or credentials

> **Note on JWS:** Signature verification is not performed. Claims validation (`exp`, `aud`, `iss`, `nonce`) is enforced, but token authenticity depends on the TLS connection to the token endpoint. Add JWKS validation on top of this package if your threat model requires it.

---

## Installation

```swift
// Package.swift
dependencies: [
    .package(url: "https://github.com/twocanoes/OIDCLite", from: "1.0.0")
]
```

---

## Quick start

### 1. Create an instance

```swift
let oidc = OIDCLite(
    discoveryURL: "https://idp.example.com/.well-known/openid-configuration",
    clientID: "your-client-id",
    clientSecret: nil,          // nil for public clients
    redirectURI: "myapp://oidc",
    scopes: ["openid", "profile", "email", "offline_access"]
)
```

Default redirect URI: `oidclite://openID`.  
Default scopes: `["openid", "profile", "email", "offline_access"]`.

### 2. Implement the delegate

```swift
extension MyController: OIDCLiteDelegate {

    func tokenResponse(tokens: OIDCLite.TokenResponse) {
        print("access_token: ", tokens.accessToken ?? "-")
        print("id_token:     ", tokens.idToken ?? "-")
        print("refresh_token:", tokens.refreshToken ?? "-")
        print("expires_in:   ", tokens.expiresIn.map { "\($0)s" } ?? "-")
        print("token_type:   ", tokens.tokenType)
        // Store tokens securely (e.g., Keychain) here.
    }

    func authFailure(message: String) {
        print("Auth failed:", message)
    }
}
```

Assign the delegate before making any API calls:

```swift
oidc.delegate = self
```

### 3. Authenticate

**Async (macOS 12+ / iOS 15+)**

```swift
@available(macOS 12.0, iOS 15.0, *)
func authenticate() async {
    do {
        try await oidc.getEndpoints()
    } catch {
        print("Discovery failed:", error.localizedDescription)
        return
    }
    startSession()
}
```

**Callback-based (macOS 10.15+ / iOS 14+)**

```swift
func authenticate() {
    // Blocks until the discovery document is fetched.
    // Call from a background thread to avoid blocking the main queue.
    oidc.getEndpoints()
    startSession()
}
```

**Starting the session**

```swift
func startSession() {
    guard let loginURL = oidc.createLoginURL() else { return }

    authSession = ASWebAuthenticationSession(
        url: loginURL,
        callbackURLScheme: "myapp"   // scheme only — no "://"
    ) { [weak self] callbackURL, error in
        guard let self, let url = callbackURL else { return }
        do {
            // Validates state, extracts the code, and exchanges it for tokens.
            // Result is delivered to delegate.tokenResponse or delegate.authFailure.
            try self.oidc.processResponseURL(url: url)
        } catch {
            print("Callback error:", error.localizedDescription)
        }
    }

    authSession?.presentationContextProvider = self
    authSession?.prefersEphemeralWebBrowserSession = true
    guard authSession?.canStart == true else { return }
    RunLoop.main.perform { self.authSession?.start() }
}
```

A complete working example is in the `Example/` folder.

---

## Token refresh

```swift
oidc.refreshTokens(storedRefreshToken)
// Result delivered to delegate.tokenResponse / delegate.authFailure
```

---

## Client authentication methods

When a `clientSecret` is supplied, it is included in the POST body by default. For providers that require HTTP Basic authentication (RFC 6749 §2.3.1), pass `basicAuth: true` to `getToken` directly:

```swift
// POST body (default — used by processResponseURL)
oidc.getToken(code: code, basicAuth: false)

// Authorization: Basic <base64(percent-encoded-clientID:percent-encoded-secret)>
oidc.getToken(code: code, basicAuth: true)
```

`processResponseURL` always calls `getToken(basicAuth: false)`. To use Basic auth, extract the code yourself and call `getToken` directly.

---

## Resource Owner Password Grant (ROPG)

For first-party or legacy flows where a browser redirect isn't possible:

```swift
// Sync
oidc.requestTokenWithROPG(username: "user@example.com", password: "secret")

// Async (macOS 12+ / iOS 15+)
@available(macOS 12.0, iOS 15.0, *)
func loginWithPassword() async throws {
    try await oidc.requestTokenWithROPG(
        username: "user@example.com",
        password: "secret",
        basicAuth: true,       // default; sends credentials in Authorization header per RFC 6749 §2.3
        overrideErrors: nil    // optional: raw 4xx response bodies to route to ropgSuccess instead of authFailure
    )
}
```

To handle non-fatal server responses (e.g., "password expired") separately, implement `ropgSuccess(errorMessage:)` on your delegate. A default no-op is provided so existing delegates don't need updating:

```swift
func ropgSuccess(errorMessage: String) {
    // e.g., navigate to password-change screen
}
```

---

## Additional authorization parameters

Pass extra query parameters for the authorization request via `additionalParameters`. Reserved OIDC parameter names (`client_id`, `state`, `nonce`, `code_challenge`, etc.) are silently ignored to prevent parameter injection:

```swift
let oidc = OIDCLite(
    discoveryURL: ..., clientID: ..., clientSecret: nil,
    redirectURI: nil, scopes: nil,
    additionalParameters: ["prompt": "login", "acr_values": "urn:mfa"]
)
```

---

## WKWebView

OIDCLite conforms to `WKNavigationDelegate`. Set it as the navigation delegate for your `WKWebView` and load the URL from `createLoginURL()`. State validation and token exchange happen automatically on the redirect.

```swift
webView.navigationDelegate = oidc
webView.load(URLRequest(url: oidc.createLoginURL()!))
```

---

## Security summary

| Concern | Status |
|---|---|
| PKCE | S256, always on |
| CSRF | Per-request random `state`, validated and consumed on redirect |
| Replay protection | Per-request random `nonce`, validated and cleared after token delivery |
| ID token claims | `exp`, `aud` (string or array), `iss`, `nonce` |
| JWS signature verification | Not implemented — relies on TLS to the token endpoint |
| Session isolation | Ephemeral `URLSession`; no shared cookies, cache, or credential store |
| POST body encoding | `application/x-www-form-urlencoded` via `URLComponents`; no string concatenation |
| Basic auth encoding | RFC 6749 §2.3.1 percent-encoding before Base64 |

---

## Notes

- Token lifecycle management (rotation, expiry tracking, secure storage) is out of scope — this package is for acquiring tokens, not managing them.
- Only public-client and confidential-client (with secret) registration models are supported.

//
//  ExampleClass.swift
//  OIDCLite Example
//
//  Demonstrates the Authorization Code + PKCE flow using ASWebAuthenticationSession.
//
//  - authenticateAsync() requires macOS 12+ / iOS 15+ and uses async/await.
//  - authenticate() works on macOS 10.15+ / iOS 14+ and uses the blocking getEndpoints().
//

import Foundation
import AuthenticationServices
import OIDCLite

// MARK: - Auth controller

class AuthController: NSObject {

    private let oidc: OIDCLite
    // Must hold a strong reference — ASWebAuthenticationSession is released if this becomes nil.
    private var authSession: ASWebAuthenticationSession?

    override init() {
        oidc = OIDCLite(
            discoveryURL: "https://idp.example.com/.well-known/openid-configuration",
            clientID: "your-client-id",
            clientSecret: nil,          // nil for public clients; supply the secret for confidential clients
            redirectURI: "myapp://oidc",
            scopes: ["openid", "profile", "email", "offline_access"]
        )
        super.init()
        oidc.delegate = self
    }

    // MARK: - Async entry point (macOS 12+ / iOS 15+)

    @available(macOS 12.0, iOS 15.0, *)
    func authenticateAsync() async {
        do {
            try await oidc.getEndpoints()
        } catch {
            print("Discovery failed: \(error.localizedDescription)")
            return
        }
        startSession()
    }

    // MARK: - Callback-based entry point (macOS 10.15+ / iOS 14+)

    func authenticate() {
        // getEndpoints() blocks until the discovery document is fetched.
        // Avoid calling this on the main thread in production — use a background queue.
        oidc.getEndpoints()
        startSession()
    }

    // MARK: - Private

    private func startSession() {
        guard let loginURL = oidc.createLoginURL() else {
            print("No authorization endpoint — make sure getEndpoints() succeeded")
            return
        }

        // callbackURLScheme is the scheme part of your redirectURI only (no "://…" or path)
        authSession = ASWebAuthenticationSession(
            url: loginURL,
            callbackURLScheme: "myapp"
        ) { [weak self] callbackURL, error in
            guard let self else { return }

            if let error {
                print("Session error: \(error.localizedDescription)")
                return
            }
            guard let url = callbackURL else {
                print("No callback URL received")
                return
            }

            do {
                // Validates the state parameter, extracts the authorization code, and
                // exchanges it for tokens. Results are delivered via OIDCLiteDelegate.
                try self.oidc.processResponseURL(url: url)
            } catch {
                print("Callback error: \(error.localizedDescription)")
            }
        }

        authSession?.presentationContextProvider = self
        authSession?.prefersEphemeralWebBrowserSession = true

        guard authSession?.canStart == true else {
            print("Unable to start ASWebAuthenticationSession")
            return
        }

        RunLoop.main.perform {
            self.authSession?.start()
        }
    }
}

// MARK: - OIDCLiteDelegate

extension AuthController: OIDCLiteDelegate {

    func tokenResponse(tokens: OIDCLite.TokenResponse) {
        print("Authentication succeeded")
        if let accessToken = tokens.accessToken  { print("  access_token:  \(accessToken)") }
        if let idToken     = tokens.idToken      { print("  id_token:      \(idToken)") }
        if let refreshToken = tokens.refreshToken { print("  refresh_token: \(refreshToken)") }
        if let expiresIn   = tokens.expiresIn    { print("  expires_in:    \(expiresIn)s") }
        print("  token_type:    \(tokens.tokenType)")

        // Store tokens securely — e.g., in the Keychain — before using them.
    }

    func authFailure(message: String) {
        print("Authentication failed: \(message)")
    }
}

// MARK: - ASWebAuthenticationPresentationContextProviding

extension AuthController: ASWebAuthenticationPresentationContextProviding {
    func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
        return ASPresentationAnchor()
    }
}

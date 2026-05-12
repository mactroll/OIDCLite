import XCTest
@testable import OIDCLite

// MARK: - Mock Delegate

final class MockOIDCLiteDelegate: OIDCLiteDelegate {
    var receivedTokens: OIDCLite.TokenResponse?
    var authFailureMessage: String?
    var tokenResponseCalled = false
    var authFailureCalled = false

    func authFailure(message: String) {
        authFailureMessage = message
        authFailureCalled = true
    }

    func tokenResponse(tokens: OIDCLite.TokenResponse) {
        receivedTokens = tokens
        tokenResponseCalled = true
    }
}

final class OIDCLiteTests: XCTestCase {

    let discoveryURL = "https://example.com/.well-known/openid-configuration"
    let clientID = "BC76BE32-289C-4A56-B5F2-ACAB2B695EDB"
    let clientSecret = "BBA8C549-49BB-49D6-A835-C9372C36C32F"
    let authEndpoint = "https://example.com/oauth/v2/auth"
    let tokenEndpoint = "https://example.com/oauth/v2/token"

    // MARK: - Init

    func testInitWithoutClientSecret() {
        let oidc = OIDCLite(discoveryURL: discoveryURL, clientID: clientID, clientSecret: nil, redirectURI: nil, scopes: nil)
        XCTAssertEqual(oidc.discoveryURL, discoveryURL)
        XCTAssertEqual(oidc.clientID, clientID)
        XCTAssertNil(oidc.clientSecret)
    }

    func testInitWithClientSecret() {
        let oidc = OIDCLite(discoveryURL: discoveryURL, clientID: clientID, clientSecret: clientSecret, redirectURI: nil, scopes: nil)
        XCTAssertEqual(oidc.discoveryURL, discoveryURL)
        XCTAssertEqual(oidc.clientID, clientID)
        XCTAssertEqual(oidc.clientSecret, clientSecret)
    }

    func testInitDefaultRedirectURI() {
        let oidc = OIDCLite(discoveryURL: discoveryURL, clientID: clientID, clientSecret: nil, redirectURI: nil, scopes: nil)
        XCTAssertEqual(oidc.redirectURI, "oidclite://openID")
    }

    func testInitCustomRedirectURI() {
        let oidc = OIDCLite(discoveryURL: discoveryURL, clientID: clientID, clientSecret: nil, redirectURI: "myapp://callback", scopes: nil)
        XCTAssertEqual(oidc.redirectURI, "myapp://callback")
    }

    func testInitDefaultScopes() {
        let oidc = OIDCLite(discoveryURL: discoveryURL, clientID: clientID, clientSecret: nil, redirectURI: nil, scopes: nil)
        XCTAssertEqual(oidc.scopes, ["openid", "profile", "email", "offline_access"])
    }

    func testInitCustomScopes() {
        let oidc = OIDCLite(discoveryURL: discoveryURL, clientID: clientID, clientSecret: nil, redirectURI: nil, scopes: ["openid", "profile"])
        XCTAssertEqual(oidc.scopes, ["openid", "profile"])
    }

    func testInitWithResource() {
        let oidc = OIDCLite(discoveryURL: discoveryURL, clientID: clientID, clientSecret: nil, redirectURI: nil, scopes: nil, resource: "https://my.resource.com")
        XCTAssertEqual(oidc.resource, "https://my.resource.com")
    }

    func testInitWithoutResourceIsNil() {
        let oidc = OIDCLite(discoveryURL: discoveryURL, clientID: clientID, clientSecret: nil, redirectURI: nil, scopes: nil)
        XCTAssertNil(oidc.resource)
    }

    // MARK: - createLoginURL structure

    func testCreateLoginURLReturnsNilWithNoEndpoint() {
        let oidc = OIDCLite(discoveryURL: discoveryURL, clientID: clientID, clientSecret: nil, redirectURI: nil, scopes: nil)
        XCTAssertNil(oidc.createLoginURL())
    }

    func testCreateLoginURLReturnsURL() {
        let oidc = makeOIDC()
        XCTAssertNotNil(oidc.createLoginURL())
    }

    func testCreateLoginURLContainsClientID() {
        let oidc = makeOIDC()
        let items = loginQueryItems(oidc)
        XCTAssertEqual(items["client_id"], clientID)
    }

    func testCreateLoginURLContainsResponseTypeCode() {
        let oidc = makeOIDC()
        let items = loginQueryItems(oidc)
        XCTAssertEqual(items["response_type"], "code")
    }

    func testCreateLoginURLContainsScopes() {
        let oidc = OIDCLite(discoveryURL: discoveryURL, clientID: clientID, clientSecret: nil, redirectURI: nil, scopes: ["openid", "profile"])
        oidc.OIDCAuthEndpoint = authEndpoint
        let items = loginQueryItems(oidc)
        XCTAssertEqual(items["scope"], "openid profile")
    }

    func testCreateLoginURLContainsRedirectURI() {
        let oidc = OIDCLite(discoveryURL: discoveryURL, clientID: clientID, clientSecret: nil, redirectURI: "myapp://callback", scopes: nil)
        oidc.OIDCAuthEndpoint = authEndpoint
        let items = loginQueryItems(oidc)
        XCTAssertEqual(items["redirect_uri"], "myapp://callback")
    }

    func testCreateLoginURLWithAdditionalParameters() {
        let extra = ["prompt": "login", "acr_values": "urn:test"]
        let oidc = OIDCLite(discoveryURL: discoveryURL, clientID: clientID, clientSecret: nil, redirectURI: nil, scopes: nil, additionalParameters: extra)
        oidc.OIDCAuthEndpoint = authEndpoint
        let items = loginQueryItems(oidc)
        XCTAssertEqual(items["prompt"], "login")
        XCTAssertEqual(items["acr_values"], "urn:test")
    }

    // MARK: - Reserved parameter protection (M2)

    func testAdditionalParametersCannotOverrideReservedParams() {
        let evil = ["prompt": "login", "client_id": "evil-client", "state": "attacker-state", "nonce": "attacker-nonce"]
        let oidc = OIDCLite(discoveryURL: discoveryURL, clientID: clientID, clientSecret: nil, redirectURI: nil, scopes: nil, additionalParameters: evil)
        oidc.OIDCAuthEndpoint = authEndpoint
        let items = loginQueryItems(oidc)
        XCTAssertEqual(items["client_id"], clientID, "Reserved param client_id must not be overridden")
        XCTAssertNotEqual(items["state"], "attacker-state", "Reserved param state must not be overridden")
        XCTAssertNotEqual(items["nonce"], "attacker-nonce", "Reserved param nonce must not be overridden")
        XCTAssertEqual(items["prompt"], "login", "Non-reserved param should be included")
    }

    // MARK: - State / CSRF (C2)

    func testCreateLoginURLContainsNonEmptyState() {
        let oidc = makeOIDC()
        let items = loginQueryItems(oidc)
        XCTAssertNotNil(items["state"])
        XCTAssertFalse(items["state"]?.isEmpty ?? true)
    }

    func testStateChangesOnEachCreateLoginURLCall() {
        let oidc = makeOIDC()
        let state1 = loginQueryItems(oidc)["state"]
        let state2 = loginQueryItems(oidc)["state"]
        XCTAssertNotEqual(state1, state2, "State must be unique per request to prevent CSRF")
    }

    // SECURITY: state returned in redirect must match the value sent, or the flow must abort.
    func testProcessResponseURLRejectsWrongState() {
        let oidc = makeOIDC()
        _ = oidc.createLoginURL()
        let url = URL(string: "oidclite://openID?code=abc123&state=WRONG_STATE")!
        XCTAssertThrowsError(try oidc.processResponseURL(url: url)) { error in
            XCTAssertEqual(error as? OIDCLiteError, OIDCLiteError.invalidState)
        }
    }

    func testProcessResponseURLRejectsMissingState() {
        let oidc = makeOIDC()
        _ = oidc.createLoginURL()
        let url = URL(string: "oidclite://openID?code=abc123")!
        XCTAssertThrowsError(try oidc.processResponseURL(url: url)) { error in
            XCTAssertEqual(error as? OIDCLiteError, OIDCLiteError.invalidState)
        }
    }

    func testProcessResponseURLRejectsCallbackWithNoLoginInitiated() {
        // No createLoginURL() → no stored state → any callback must be rejected
        let oidc = makeOIDC()
        let url = URL(string: "oidclite://openID?code=abc123&state=some_state")!
        XCTAssertThrowsError(try oidc.processResponseURL(url: url)) { error in
            XCTAssertEqual(error as? OIDCLiteError, OIDCLiteError.invalidState)
        }
    }

    func testProcessResponseURLAcceptsCorrectState() throws {
        let oidc = makeOIDC()
        let loginURL = oidc.createLoginURL()!
        let state = urlQueryItems(loginURL)["state"]!
        let callbackURL = URL(string: "oidclite://openID?code=abc123&state=\(state)")!
        XCTAssertNoThrow(try oidc.processResponseURL(url: callbackURL))
    }

    func testStateIsConsumedAfterSuccessfulValidation() throws {
        let oidc = makeOIDC()
        let loginURL = oidc.createLoginURL()!
        let state = urlQueryItems(loginURL)["state"]!
        let callbackURL = URL(string: "oidclite://openID?code=abc123&state=\(state)")!
        try? oidc.processResponseURL(url: callbackURL)
        // Replaying the same URL must now fail
        XCTAssertThrowsError(try oidc.processResponseURL(url: callbackURL)) { error in
            XCTAssertEqual(error as? OIDCLiteError, OIDCLiteError.invalidState)
        }
    }

    // MARK: - Redirect URI validation (M5)

    func testProcessResponseURLRejectsWrongRedirectURI() {
        let oidc = makeOIDC()
        _ = oidc.createLoginURL()
        let url = URL(string: "evil://callback?code=abc123&state=any")!
        XCTAssertThrowsError(try oidc.processResponseURL(url: url)) { error in
            XCTAssertEqual(error as? OIDCLiteError, OIDCLiteError.invalidRedirectURI)
        }
    }

    // MARK: - processResponseURL code extraction (C5)

    func testProcessResponseURLThrowsWhenNoCode() {
        let oidc = makeOIDC()
        let loginURL = oidc.createLoginURL()!
        let state = urlQueryItems(loginURL)["state"]!
        let url = URL(string: "oidclite://openID?error=access_denied&state=\(state)")!
        XCTAssertThrowsError(try oidc.processResponseURL(url: url)) { error in
            XCTAssertEqual(error as? OIDCLiteError, OIDCLiteError.unableToFindCode)
        }
    }

    func testProcessResponseURLThrowsForEmptyQuery() {
        let oidc = makeOIDC()
        _ = oidc.createLoginURL()
        let url = URL(string: "oidclite://openID")!
        XCTAssertThrowsError(try oidc.processResponseURL(url: url))
    }

    // MARK: - PKCE (C4 / C5)

    func testCreateLoginURLContainsPKCEChallenge() {
        let oidc = makeOIDC()
        let items = loginQueryItems(oidc)
        XCTAssertNotNil(items["code_challenge"])
        XCTAssertFalse(items["code_challenge"]?.isEmpty ?? true)
    }

    func testCreateLoginURLUsesSHA256PKCEMethod() {
        let oidc = makeOIDC()
        let items = loginQueryItems(oidc)
        XCTAssertEqual(items["code_challenge_method"], "S256", "Must use S256, not plain")
    }

    func testPKCEChallengeIsBase64URLEncoded() {
        let oidc = makeOIDC()
        let challenge = loginQueryItems(oidc)["code_challenge"] ?? ""
        XCTAssertFalse(challenge.contains("+"), "code_challenge must be base64url (no +)")
        XCTAssertFalse(challenge.contains("/"), "code_challenge must be base64url (no /)")
        XCTAssertFalse(challenge.contains("="), "code_challenge must be base64url (no =)")
    }

    func testCodeVerifierMeetsRFC7636LengthRequirements() {
        let oidc = makeOIDC()
        _ = oidc.createLoginURL() // verifier is generated here
        let len = oidc.codeVerifier.count
        XCTAssertGreaterThanOrEqual(len, 43, "code_verifier too short (RFC 7636 min: 43)")
        XCTAssertLessThanOrEqual(len, 128, "code_verifier too long (RFC 7636 max: 128)")
    }

    func testCodeVerifierIsUniquePerInstance() {
        let oidc1 = makeOIDC()
        let oidc2 = makeOIDC()
        _ = oidc1.createLoginURL()
        _ = oidc2.createLoginURL()
        XCTAssertNotEqual(oidc1.codeVerifier, oidc2.codeVerifier)
    }

    func testCodeVerifierRegeneratedPerLoginURLCall() {
        let oidc = makeOIDC()
        _ = oidc.createLoginURL()
        let v1 = oidc.codeVerifier
        _ = oidc.createLoginURL()
        let v2 = oidc.codeVerifier
        XCTAssertNotEqual(v1, v2, "code_verifier must be regenerated for each authorization request (RFC 7636)")
    }

    // MARK: - Nonce (C3 / replay protection)

    func testCreateLoginURLContainsNonce() {
        let oidc = makeOIDC()
        let items = loginQueryItems(oidc)
        XCTAssertNotNil(items["nonce"])
        XCTAssertFalse(items["nonce"]?.isEmpty ?? true)
    }

    func testNonceChangesOnEachCreateLoginURLCall() {
        let oidc = makeOIDC()
        let n1 = loginQueryItems(oidc)["nonce"]
        let n2 = loginQueryItems(oidc)["nonce"]
        XCTAssertNotEqual(n1, n2, "Nonce must be unique per request to prevent replay attacks")
    }

    func testNonceIsStoredAfterCreateLoginURL() {
        let oidc = makeOIDC()
        _ = oidc.createLoginURL()
        XCTAssertNotNil(oidc.nonce, "Nonce must be stored so it can be validated in the ID token")
    }

    // MARK: - Token response parsing (basic)

    func testProcessOIDCResponseParsesAccessToken() {
        let (oidc, delegate) = makeOIDCWithDelegate()
        oidc.processOIDCResponse(jsonData(["access_token": "test_at", "token_type": "Bearer"]))
        XCTAssertTrue(delegate.tokenResponseCalled)
        XCTAssertEqual(delegate.receivedTokens?.accessToken, "test_at")
    }

    func testProcessOIDCResponseParsesRefreshToken() {
        let (oidc, delegate) = makeOIDCWithDelegate()
        oidc.processOIDCResponse(jsonData(["access_token": "at", "refresh_token": "test_rt", "token_type": "Bearer"]))
        XCTAssertEqual(delegate.receivedTokens?.refreshToken, "test_rt")
    }

    func testProcessOIDCResponseIncludesFullJSONDict() {
        let (oidc, delegate) = makeOIDCWithDelegate()
        oidc.processOIDCResponse(jsonData(["access_token": "at", "token_type": "Bearer", "custom_field": "custom_value"]))
        XCTAssertEqual(delegate.receivedTokens?.jsonDict?["custom_field"] as? String, "custom_value")
    }

    func testProcessOIDCResponseCallsAuthFailureOnInvalidJSON() {
        let (oidc, delegate) = makeOIDCWithDelegate()
        oidc.processOIDCResponse("not json".data(using: .utf8)!)
        XCTAssertTrue(delegate.authFailureCalled)
        XCTAssertFalse(delegate.tokenResponseCalled)
    }

    func testProcessOIDCResponseHandlesEmptyTokenFields() {
        let (oidc, delegate) = makeOIDCWithDelegate()
        oidc.processOIDCResponse(jsonData(["token_type": "Bearer"]))
        XCTAssertTrue(delegate.tokenResponseCalled)
        XCTAssertNil(delegate.receivedTokens?.accessToken)
        XCTAssertNil(delegate.receivedTokens?.idToken)
        XCTAssertNil(delegate.receivedTokens?.refreshToken)
    }

    // MARK: - ID token claim validation (C1)

    func testProcessOIDCResponseAcceptsValidIDToken() {
        let (oidc, delegate) = makeOIDCWithDelegate()
        _ = oidc.createLoginURL()
        let token = makeJWT(oidc: oidc)
        oidc.processOIDCResponse(jsonData(["access_token": "at", "id_token": token, "token_type": "Bearer"]))
        XCTAssertTrue(delegate.tokenResponseCalled)
        XCTAssertFalse(delegate.authFailureCalled)
        XCTAssertEqual(delegate.receivedTokens?.idToken, token)
    }

    func testProcessOIDCResponseRejectsMalformedIDToken() {
        let (oidc, delegate) = makeOIDCWithDelegate()
        oidc.processOIDCResponse(jsonData(["access_token": "at", "id_token": "not.a.jwt.with.too.many.dots", "token_type": "Bearer"]))
        XCTAssertTrue(delegate.authFailureCalled)
        XCTAssertFalse(delegate.tokenResponseCalled)
    }

    func testProcessOIDCResponseRejectsExpiredIDToken() {
        let (oidc, delegate) = makeOIDCWithDelegate()
        _ = oidc.createLoginURL()
        let expired = makeJWT(oidc: oidc, expOffset: -3600)
        oidc.processOIDCResponse(jsonData(["access_token": "at", "id_token": expired, "token_type": "Bearer"]))
        XCTAssertTrue(delegate.authFailureCalled)
        XCTAssertFalse(delegate.tokenResponseCalled)
        XCTAssertTrue(delegate.authFailureMessage?.contains("expired") ?? false)
    }

    func testProcessOIDCResponseRejectsWrongAudience() {
        let (oidc, delegate) = makeOIDCWithDelegate()
        _ = oidc.createLoginURL()
        let wrongAud = makeJWT(oidc: oidc, overrideClaims: ["aud": "completely-different-client"])
        oidc.processOIDCResponse(jsonData(["access_token": "at", "id_token": wrongAud, "token_type": "Bearer"]))
        XCTAssertTrue(delegate.authFailureCalled)
        XCTAssertTrue(delegate.authFailureMessage?.contains("audience") ?? false)
    }

    func testProcessOIDCResponseAcceptsArrayAudienceContainingClientID() {
        let (oidc, delegate) = makeOIDCWithDelegate()
        _ = oidc.createLoginURL()
        let multiAud = makeJWT(oidc: oidc, overrideClaims: ["aud": [clientID, "other-resource"]])
        oidc.processOIDCResponse(jsonData(["access_token": "at", "id_token": multiAud, "token_type": "Bearer"]))
        XCTAssertTrue(delegate.tokenResponseCalled)
        XCTAssertFalse(delegate.authFailureCalled)
    }

    func testProcessOIDCResponseRejectsWrongIssuer() {
        let (oidc, delegate) = makeOIDCWithDelegate()
        oidc.discoveredIssuer = "https://example.com"
        _ = oidc.createLoginURL()
        let wrongIss = makeJWT(oidc: oidc, overrideClaims: ["iss": "https://evil.example.com"])
        oidc.processOIDCResponse(jsonData(["access_token": "at", "id_token": wrongIss, "token_type": "Bearer"]))
        XCTAssertTrue(delegate.authFailureCalled)
        XCTAssertTrue(delegate.authFailureMessage?.contains("issuer") ?? false)
    }

    func testProcessOIDCResponseAcceptsMatchingIssuer() {
        let (oidc, delegate) = makeOIDCWithDelegate()
        oidc.discoveredIssuer = "https://example.com"
        _ = oidc.createLoginURL()
        let goodIss = makeJWT(oidc: oidc, overrideClaims: ["iss": "https://example.com"])
        oidc.processOIDCResponse(jsonData(["access_token": "at", "id_token": goodIss, "token_type": "Bearer"]))
        XCTAssertTrue(delegate.tokenResponseCalled)
        XCTAssertFalse(delegate.authFailureCalled)
    }

    func testProcessOIDCResponseRejectsNonceMismatch() {
        let (oidc, delegate) = makeOIDCWithDelegate()
        _ = oidc.createLoginURL()
        let wrongNonce = makeJWT(oidc: oidc, overrideClaims: ["nonce": "attacker-nonce"])
        oidc.processOIDCResponse(jsonData(["access_token": "at", "id_token": wrongNonce, "token_type": "Bearer"]))
        XCTAssertTrue(delegate.authFailureCalled)
        XCTAssertTrue(delegate.authFailureMessage?.contains("nonce") ?? false)
    }

    func testProcessOIDCResponseClearsNonceAfterValidation() {
        let (oidc, delegate) = makeOIDCWithDelegate()
        _ = oidc.createLoginURL()
        let token = makeJWT(oidc: oidc)
        oidc.processOIDCResponse(jsonData(["access_token": "at", "id_token": token, "token_type": "Bearer"]))
        XCTAssertTrue(delegate.tokenResponseCalled)
        XCTAssertNil(oidc.nonce, "Nonce must be cleared after successful validation to prevent reuse")
    }

    // MARK: - base64URLEncoded

    func testBase64URLEncodedReplacesPlus() {
        XCTAssertEqual("abc+def".base64URLEncoded(), "abc-def")
    }

    func testBase64URLEncodedReplacesSlash() {
        XCTAssertEqual("abc/def".base64URLEncoded(), "abc_def")
    }

    func testBase64URLEncodedRemovesPadding() {
        XCTAssertEqual("abc==".base64URLEncoded(), "abc")
    }

    func testBase64URLEncodedHandlesEmptyString() {
        XCTAssertEqual("".base64URLEncoded(), "")
    }

    func testBase64URLEncodedHandlesAllThreeSubstitutions() {
        let result = "aB+c/d=".base64URLEncoded()
        XCTAssertFalse(result.contains("+"))
        XCTAssertFalse(result.contains("/"))
        XCTAssertFalse(result.contains("="))
    }

    // MARK: - Helpers

    private func makeOIDC(redirectURI: String? = nil, scopes: [String]? = nil) -> OIDCLite {
        let oidc = OIDCLite(discoveryURL: discoveryURL, clientID: clientID, clientSecret: nil, redirectURI: redirectURI, scopes: scopes)
        oidc.OIDCAuthEndpoint = authEndpoint
        oidc.OIDCTokenEndpoint = tokenEndpoint
        return oidc
    }

    private func makeOIDCWithDelegate() -> (OIDCLite, MockOIDCLiteDelegate) {
        let oidc = makeOIDC()
        let delegate = MockOIDCLiteDelegate()
        oidc.delegate = delegate
        return (oidc, delegate)
    }

    private func loginQueryItems(_ oidc: OIDCLite) -> [String: String] {
        guard let url = oidc.createLoginURL() else { return [:] }
        return urlQueryItems(url)
    }

    private func urlQueryItems(_ url: URL) -> [String: String] {
        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
              let items = components.queryItems else { return [:] }
        return Dictionary(uniqueKeysWithValues: items.compactMap { item in
            guard let value = item.value else { return nil }
            return (item.name, value)
        })
    }

    private func jsonData(_ dict: [String: Any]) -> Data {
        return try! JSONSerialization.data(withJSONObject: dict)
    }

    /// Build a minimal signed-looking JWT for testing claim validation.
    /// `overrideClaims` replaces individual claims; nonce and aud default to oidc's values.
    private func makeJWT(oidc: OIDCLite, overrideClaims: [String: Any] = [:], expOffset: TimeInterval = 3600) -> String {
        let header = Data(#"{"alg":"RS256","typ":"JWT"}"#.utf8).base64EncodedString().base64URLEncoded()
        var claims: [String: Any] = [
            "iss": "https://example.com",
            "aud": oidc.clientID,
            "exp": Date().timeIntervalSince1970 + expOffset,
            "iat": Date().timeIntervalSince1970,
        ]
        if let storedNonce = oidc.nonce { claims["nonce"] = storedNonce }
        for (k, v) in overrideClaims { claims[k] = v }
        let payload = (try! JSONSerialization.data(withJSONObject: claims)).base64EncodedString().base64URLEncoded()
        return "\(header).\(payload).fakesig"
    }
}

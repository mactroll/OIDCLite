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

    // MARK: - State / CSRF

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

    // SECURITY: state returned in redirect must be validated against the value sent in the request.
    // Without this check, an attacker can forge a redirect and hijack the auth flow.
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
        // No createLoginURL() called — no state set; any callback must be rejected.
        let oidc = makeOIDC()
        let url = URL(string: "oidclite://openID?code=abc123&state=some_state")!
        XCTAssertThrowsError(try oidc.processResponseURL(url: url)) { error in
            XCTAssertEqual(error as? OIDCLiteError, OIDCLiteError.invalidState)
        }
    }

    func testProcessResponseURLAcceptsCorrectState() throws {
        let oidc = makeOIDC()
        oidc.OIDCTokenEndpoint = tokenEndpoint
        let loginURL = oidc.createLoginURL()!
        let state = urlQueryItems(loginURL)["state"]!
        let callbackURL = URL(string: "oidclite://openID?code=abc123&state=\(state)")!
        XCTAssertNoThrow(try oidc.processResponseURL(url: callbackURL))
    }

    // MARK: - processResponseURL code extraction

    func testProcessResponseURLThrowsWhenNoCode() {
        let oidc = makeOIDC()
        oidc.OIDCTokenEndpoint = tokenEndpoint
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

    // MARK: - PKCE

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
        // RFC 7636 §4.1: code_verifier must be 43–128 characters
        let oidc = makeOIDC()
        let len = oidc.codeVerifier.count
        XCTAssertGreaterThanOrEqual(len, 43, "code_verifier too short (RFC 7636 min: 43)")
        XCTAssertLessThanOrEqual(len, 128, "code_verifier too long (RFC 7636 max: 128)")
    }

    func testCodeVerifierIsUniquePerInstance() {
        let v1 = makeOIDC().codeVerifier
        let v2 = makeOIDC().codeVerifier
        XCTAssertNotEqual(v1, v2)
    }

    // MARK: - Nonce (replay protection)

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

    // MARK: - Token response parsing

    func testProcessOIDCResponseParsesAccessToken() {
        let (oidc, delegate) = makeOIDCWithDelegate()
        oidc.processOIDCResponse(jsonData(["access_token": "test_at", "token_type": "Bearer"]))
        XCTAssertTrue(delegate.tokenResponseCalled)
        XCTAssertEqual(delegate.receivedTokens?.accessToken, "test_at")
    }

    func testProcessOIDCResponseParsesIDToken() {
        let (oidc, delegate) = makeOIDCWithDelegate()
        oidc.processOIDCResponse(jsonData(["access_token": "at", "id_token": "test_idt", "token_type": "Bearer"]))
        XCTAssertEqual(delegate.receivedTokens?.idToken, "test_idt")
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
}

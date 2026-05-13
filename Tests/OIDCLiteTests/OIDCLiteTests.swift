import XCTest
import CryptoKit
import Security
@testable import OIDCLite

// MARK: - Mock Delegate

final class MockOIDCLiteDelegate: OIDCLiteDelegate {
    var receivedTokens: OIDCLite.TokenResponse?
    var authFailureMessage: String?
    var tokenResponseCalled = false
    var authFailureCalled = false
    var ropgSuccessCalled = false
    var ropgSuccessMessage: String?
    var onCompletion: (() -> Void)?

    func authFailure(message: String) {
        authFailureMessage = message
        authFailureCalled = true
        onCompletion?()
    }

    func tokenResponse(tokens: OIDCLite.TokenResponse) {
        receivedTokens = tokens
        tokenResponseCalled = true
        onCompletion?()
    }

    func ropgSuccess(errorMessage: String) {
        ropgSuccessCalled = true
        ropgSuccessMessage = errorMessage
        onCompletion?()
    }
}

// Intercepts URLSession requests so tests can inspect outgoing requests without hitting the network.
final class MockURLProtocol: URLProtocol {
    static var requestHandler: ((URLRequest) throws -> (HTTPURLResponse, Data))?
    static var capturedRequest: URLRequest?

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        MockURLProtocol.capturedRequest = request
        guard let handler = MockURLProtocol.requestHandler else {
            client?.urlProtocol(self, didFailWithError: URLError(.unsupportedURL))
            return
        }
        do {
            let (response, data) = try handler(request)
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            client?.urlProtocol(self, didLoad: data)
            client?.urlProtocolDidFinishLoading(self)
        } catch {
            client?.urlProtocol(self, didFailWithError: error)
        }
    }

    override func stopLoading() {}
}

final class OIDCLiteTests: XCTestCase {

    override func setUp() {
        super.setUp()
        MockURLProtocol.capturedRequest = nil
        MockURLProtocol.requestHandler = nil
    }

    let discoveryURL = "https://example.com/.well-known/openid-configuration"
    let clientID = "BC76BE32-289C-4A56-B5F2-ACAB2B695EDB"
    let clientSecret = "BBA8C549-49BB-49D6-A835-C9372C36C32F"
    let authEndpoint = "https://example.com/oauth/v2/auth"
    let tokenEndpoint = "https://example.com/oauth/v2/token"
    let jwksURL = "https://example.com/.well-known/jwks.json"

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

    // MARK: - TokenResponse extended fields

    func testProcessOIDCResponseParsesExpiresInAsInt() {
        let (oidc, delegate) = makeOIDCWithDelegate()
        oidc.processOIDCResponse(jsonData(["access_token": "at", "token_type": "Bearer", "expires_in": 3600]))
        XCTAssertEqual(delegate.receivedTokens?.expiresIn, 3600)
    }

    func testProcessOIDCResponseParsesExpiresInAsString() {
        let (oidc, delegate) = makeOIDCWithDelegate()
        oidc.processOIDCResponse(jsonData(["access_token": "at", "token_type": "Bearer", "expires_in": "7200"]))
        XCTAssertEqual(delegate.receivedTokens?.expiresIn, 7200)
    }

    func testProcessOIDCResponseExpiresInNilWhenAbsent() {
        let (oidc, delegate) = makeOIDCWithDelegate()
        oidc.processOIDCResponse(jsonData(["access_token": "at", "token_type": "Bearer"]))
        XCTAssertNil(delegate.receivedTokens?.expiresIn)
    }

    func testProcessOIDCResponseParsesTokenType() {
        let (oidc, delegate) = makeOIDCWithDelegate()
        oidc.processOIDCResponse(jsonData(["access_token": "at", "token_type": "Bearer"]))
        XCTAssertEqual(delegate.receivedTokens?.tokenType, "Bearer")
    }

    func testProcessOIDCResponseDefaultsTokenTypeWhenAbsent() {
        let (oidc, delegate) = makeOIDCWithDelegate()
        oidc.processOIDCResponse(jsonData(["access_token": "at"]))
        XCTAssertEqual(delegate.receivedTokens?.tokenType, "bearer")
    }

    func testProcessOIDCResponseParsesScope() {
        let (oidc, delegate) = makeOIDCWithDelegate()
        oidc.processOIDCResponse(jsonData(["access_token": "at", "token_type": "Bearer", "scope": "openid profile"]))
        XCTAssertEqual(delegate.receivedTokens?.scope, "openid profile")
    }

    func testProcessOIDCResponseScopeNilWhenAbsent() {
        let (oidc, delegate) = makeOIDCWithDelegate()
        oidc.processOIDCResponse(jsonData(["access_token": "at", "token_type": "Bearer"]))
        XCTAssertNil(delegate.receivedTokens?.scope)
    }

    // MARK: - getToken request structure (H1 / basic-auth feature)

    func testGetTokenWithBasicAuthSetsAuthorizationHeader() {
        let (oidc, delegate) = makeOIDCWithMockSession(secret: clientSecret)
        MockURLProtocol.requestHandler = { _ in (self.makeHTTPResponse(), self.tokenSuccessData()) }
        _ = oidc.createLoginURL()
        waitForDelegate(delegate) { oidc.getToken(code: "abc", basicAuth: true) }
        let header = MockURLProtocol.capturedRequest?.value(forHTTPHeaderField: "Authorization")
        XCTAssertNotNil(header, "Authorization header must be set when basicAuth is true")
        XCTAssertTrue(header?.hasPrefix("Basic ") ?? false)
    }

    func testGetTokenWithBasicAuthHeaderEncodesClientIDAndSecret() {
        let (oidc, delegate) = makeOIDCWithMockSession(secret: clientSecret)
        MockURLProtocol.requestHandler = { _ in (self.makeHTTPResponse(), self.tokenSuccessData()) }
        _ = oidc.createLoginURL()
        waitForDelegate(delegate) { oidc.getToken(code: "abc", basicAuth: true) }
        let header = MockURLProtocol.capturedRequest?.value(forHTTPHeaderField: "Authorization") ?? ""
        let b64 = String(header.dropFirst("Basic ".count))
        let decoded = String(data: Data(base64Encoded: b64) ?? Data(), encoding: .utf8) ?? ""
        XCTAssertTrue(decoded.contains(clientID), "Authorization header must contain clientID")
        XCTAssertTrue(decoded.contains(clientSecret), "Authorization header must contain clientSecret")
    }

    func testGetTokenWithBasicAuthOmitsClientSecretFromBody() {
        let (oidc, delegate) = makeOIDCWithMockSession(secret: clientSecret)
        MockURLProtocol.requestHandler = { _ in (self.makeHTTPResponse(), self.tokenSuccessData()) }
        _ = oidc.createLoginURL()
        waitForDelegate(delegate) { oidc.getToken(code: "abc", basicAuth: true) }
        let body = rawFormBody(from: MockURLProtocol.capturedRequest)
        XCTAssertFalse(body.contains("client_secret"), "client_secret must not appear in body when using Basic auth (RFC 6749 §2.3)")
    }

    func testGetTokenWithoutBasicAuthIncludesClientSecretInBody() {
        let (oidc, delegate) = makeOIDCWithMockSession(secret: clientSecret)
        MockURLProtocol.requestHandler = { _ in (self.makeHTTPResponse(), self.tokenSuccessData()) }
        _ = oidc.createLoginURL()
        waitForDelegate(delegate) { oidc.getToken(code: "abc", basicAuth: false) }
        let params = parseFormBody(from: MockURLProtocol.capturedRequest)
        XCTAssertEqual(params["client_secret"], clientSecret)
    }

    func testGetTokenWithoutBasicAuthHasNoAuthorizationHeader() {
        let (oidc, delegate) = makeOIDCWithMockSession(secret: clientSecret)
        MockURLProtocol.requestHandler = { _ in (self.makeHTTPResponse(), self.tokenSuccessData()) }
        _ = oidc.createLoginURL()
        waitForDelegate(delegate) { oidc.getToken(code: "abc", basicAuth: false) }
        XCTAssertNil(MockURLProtocol.capturedRequest?.value(forHTTPHeaderField: "Authorization"))
    }

    func testGetTokenBodyContainsGrantType() {
        let (oidc, delegate) = makeOIDCWithMockSession()
        MockURLProtocol.requestHandler = { _ in (self.makeHTTPResponse(), self.tokenSuccessData()) }
        _ = oidc.createLoginURL()
        waitForDelegate(delegate) { oidc.getToken(code: "abc") }
        XCTAssertEqual(parseFormBody(from: MockURLProtocol.capturedRequest)["grant_type"], "authorization_code")
    }

    func testGetTokenBodyContainsCodeVerifier() {
        let (oidc, delegate) = makeOIDCWithMockSession()
        MockURLProtocol.requestHandler = { _ in (self.makeHTTPResponse(), self.tokenSuccessData()) }
        _ = oidc.createLoginURL()
        let verifier = oidc.codeVerifier
        waitForDelegate(delegate) { oidc.getToken(code: "abc") }
        XCTAssertEqual(parseFormBody(from: MockURLProtocol.capturedRequest)["code_verifier"], verifier)
    }

    // MARK: - refreshTokens URL encoding (H1)

    func testRefreshTokensPercentEncodesSpecialCharsInToken() {
        let (oidc, delegate) = makeOIDCWithMockSession()
        MockURLProtocol.requestHandler = { _ in (self.makeHTTPResponse(), self.tokenSuccessData()) }
        waitForDelegate(delegate) { oidc.refreshTokens("a&b=c") }
        let body = rawFormBody(from: MockURLProtocol.capturedRequest)
        XCTAssertFalse(body.contains("refresh_token=a&b=c"), "Unencoded & would corrupt the POST body")
        XCTAssertTrue(body.contains("refresh_token=a%26b%3Dc"), "& must encode to %26, = must encode to %3D")
    }

    // MARK: - requestTokenWithROPG request structure (H5)

    func testROPGSyncUsesBasicAuthHeader() {
        let (oidc, delegate) = makeOIDCWithMockSession(secret: clientSecret)
        MockURLProtocol.requestHandler = { _ in (self.makeHTTPResponse(), self.tokenSuccessData()) }
        waitForDelegate(delegate) { oidc.requestTokenWithROPG(username: "user", password: "pass") }
        let header = MockURLProtocol.capturedRequest?.value(forHTTPHeaderField: "Authorization")
        XCTAssertTrue(header?.hasPrefix("Basic ") ?? false, "ROPG must use HTTP Basic auth per RFC 6749 §2.3")
    }

    func testROPGSyncBodyOmitsClientCredentials() {
        let (oidc, delegate) = makeOIDCWithMockSession(secret: clientSecret)
        MockURLProtocol.requestHandler = { _ in (self.makeHTTPResponse(), self.tokenSuccessData()) }
        waitForDelegate(delegate) { oidc.requestTokenWithROPG(username: "user", password: "pass") }
        let body = rawFormBody(from: MockURLProtocol.capturedRequest)
        XCTAssertFalse(body.contains("client_secret"), "ROPG must not include client_secret in body when using Basic auth")
        XCTAssertFalse(body.contains("client_id"), "ROPG must not include client_id in body when using Basic auth")
    }

    func testROPGSyncBodyContainsGrantTypePassword() {
        let (oidc, delegate) = makeOIDCWithMockSession()
        MockURLProtocol.requestHandler = { _ in (self.makeHTTPResponse(), self.tokenSuccessData()) }
        waitForDelegate(delegate) { oidc.requestTokenWithROPG(username: "user", password: "pass") }
        XCTAssertEqual(parseFormBody(from: MockURLProtocol.capturedRequest)["grant_type"], "password")
    }

    func testROPGSyncBodyContainsUsernameAndPassword() {
        let (oidc, delegate) = makeOIDCWithMockSession()
        MockURLProtocol.requestHandler = { _ in (self.makeHTTPResponse(), self.tokenSuccessData()) }
        waitForDelegate(delegate) { oidc.requestTokenWithROPG(username: "testuser", password: "testpass") }
        let params = parseFormBody(from: MockURLProtocol.capturedRequest)
        XCTAssertEqual(params["username"], "testuser")
        XCTAssertEqual(params["password"], "testpass")
    }

    // MARK: - OAuth error message scoping (H4)

    func testOAuthErrorIncludesErrorCode() {
        let (oidc, delegate) = makeOIDCWithMockSession()
        MockURLProtocol.requestHandler = { _ in
            (self.makeHTTPResponse(status: 401), self.jsonData(["error": "invalid_client", "error_description": "Bad credentials"]))
        }
        waitForDelegate(delegate) { oidc.getToken(code: "abc") }
        XCTAssertTrue(delegate.authFailureMessage?.contains("invalid_client") ?? false)
    }

    func testOAuthErrorIncludesDescription() {
        let (oidc, delegate) = makeOIDCWithMockSession()
        MockURLProtocol.requestHandler = { _ in
            (self.makeHTTPResponse(status: 401), self.jsonData(["error": "invalid_client", "error_description": "Bad credentials"]))
        }
        waitForDelegate(delegate) { oidc.getToken(code: "abc") }
        XCTAssertTrue(delegate.authFailureMessage?.contains("Bad credentials") ?? false)
    }

    func testOAuthErrorIncludesErrorURI() {
        let (oidc, delegate) = makeOIDCWithMockSession()
        MockURLProtocol.requestHandler = { _ in
            (self.makeHTTPResponse(status: 400), self.jsonData(["error": "invalid_request", "error_uri": "https://example.com/errors/invalid_request"]))
        }
        waitForDelegate(delegate) { oidc.getToken(code: "abc") }
        XCTAssertTrue(delegate.authFailureMessage?.contains("https://example.com/errors/invalid_request") ?? false)
    }

    func testOAuthErrorExcludesNonStandardFields() {
        let (oidc, delegate) = makeOIDCWithMockSession()
        MockURLProtocol.requestHandler = { _ in
            (self.makeHTTPResponse(status: 500), self.jsonData(["error": "server_error", "correlation_id": "secret-id", "trace": "internal-trace"]))
        }
        waitForDelegate(delegate) { oidc.getToken(code: "abc") }
        XCTAssertFalse(delegate.authFailureMessage?.contains("secret-id") ?? true, "Non-standard fields must not leak to caller")
        XCTAssertFalse(delegate.authFailureMessage?.contains("internal-trace") ?? true, "Non-standard fields must not leak to caller")
    }

    // MARK: - JWT signature verification

    @available(macOS 12.0, *)
    func testValidateSignatureNoJWKSURI() async {
        let (oidc, _) = makeOIDCWithMockSession()
        // jwksURI intentionally not set — should throw before making any network call
        do {
            try await oidc.validateIDTokenSignature("a.b.c")
            XCTFail("Expected invalidIDToken error")
        } catch OIDCLiteError.invalidIDToken(let reason) {
            XCTAssertTrue(reason.contains("JWKS URI"), "Got: \(reason)")
        } catch {
            XCTFail("Unexpected error type: \(error)")
        }
    }

    @available(macOS 12.0, *)
    func testValidateSignatureMalformedJWT() async {
        let (oidc, _) = makeOIDCWithMockSession()
        oidc.jwksURI = jwksURL
        // Single part — no dots — should fail before any JWKS fetch
        do {
            try await oidc.validateIDTokenSignature("not-a-jwt")
            XCTFail("Expected invalidIDToken error")
        } catch OIDCLiteError.invalidIDToken(let reason) {
            XCTAssertTrue(reason.contains("malformed"), "Got: \(reason)")
        } catch {
            XCTFail("Unexpected error type: \(error)")
        }
    }

    @available(macOS 12.0, *)
    func testValidateSignatureKidNotInJWKS() async throws {
        let (oidc, _) = makeOIDCWithMockSession()
        oidc.jwksURI = jwksURL
        let key = P256.Signing.PrivateKey()
        // JWT signed with kid "expected-kid"; JWKS only has kid "different-kid"
        let jwt = try makeES256SignedJWT(claims: [:], kid: "expected-kid", privateKey: key)
        let jwk = makeES256JWK(publicKey: key.publicKey, kid: "different-kid")
        MockURLProtocol.requestHandler = { _ in (self.makeJWKSResponse(), self.makeJWKSData(keys: [jwk])) }
        do {
            try await oidc.validateIDTokenSignature(jwt)
            XCTFail("Expected invalidIDToken error")
        } catch OIDCLiteError.invalidIDToken(let reason) {
            XCTAssertTrue(reason.contains("expected-kid"), "Error should name the missing kid. Got: \(reason)")
        } catch {
            XCTFail("Unexpected error type: \(error)")
        }
    }

    @available(macOS 12.0, *)
    func testValidateSignatureUnsupportedAlgorithm() async throws {
        let (oidc, _) = makeOIDCWithMockSession()
        oidc.jwksURI = jwksURL
        // JWT header claims HS256 (unsupported); no kid so key lookup falls back to first JWKS entry
        let key = P256.Signing.PrivateKey()
        let header = Data(#"{"alg":"HS256","typ":"JWT"}"#.utf8).base64EncodedString().base64URLEncoded()
        let payload = Data(#"{"sub":"test"}"#.utf8).base64EncodedString().base64URLEncoded()
        let jwt = "\(header).\(payload).fakesig"
        let jwk = makeES256JWK(publicKey: key.publicKey, kid: "k1")
        MockURLProtocol.requestHandler = { _ in (self.makeJWKSResponse(), self.makeJWKSData(keys: [jwk])) }
        do {
            try await oidc.validateIDTokenSignature(jwt)
            XCTFail("Expected invalidIDToken error")
        } catch OIDCLiteError.invalidIDToken(let reason) {
            XCTAssertTrue(reason.contains("HS256"), "Error should name the algorithm. Got: \(reason)")
        } catch {
            XCTFail("Unexpected error type: \(error)")
        }
    }

    @available(macOS 12.0, *)
    func testValidateSignatureES256Valid() async throws {
        let (oidc, _) = makeOIDCWithMockSession()
        oidc.jwksURI = jwksURL
        let key = P256.Signing.PrivateKey()
        let jwt = try makeES256SignedJWT(claims: ["sub": "user1"], kid: "k1", privateKey: key)
        let jwk = makeES256JWK(publicKey: key.publicKey, kid: "k1")
        MockURLProtocol.requestHandler = { _ in (self.makeJWKSResponse(), self.makeJWKSData(keys: [jwk])) }
        try await oidc.validateIDTokenSignature(jwt)
    }

    @available(macOS 12.0, *)
    func testValidateSignatureES256WrongKey() async throws {
        let (oidc, _) = makeOIDCWithMockSession()
        oidc.jwksURI = jwksURL
        let signingKey = P256.Signing.PrivateKey()
        let differentKey = P256.Signing.PrivateKey()
        let jwt = try makeES256SignedJWT(claims: ["sub": "user1"], kid: "k1", privateKey: signingKey)
        let jwk = makeES256JWK(publicKey: differentKey.publicKey, kid: "k1") // wrong public key
        MockURLProtocol.requestHandler = { _ in (self.makeJWKSResponse(), self.makeJWKSData(keys: [jwk])) }
        do {
            try await oidc.validateIDTokenSignature(jwt)
            XCTFail("Expected invalidIDToken error for mismatched key")
        } catch OIDCLiteError.invalidIDToken(let reason) {
            XCTAssertTrue(reason.contains("EC signature"), "Got: \(reason)")
        } catch {
            XCTFail("Unexpected error type: \(error)")
        }
    }

    @available(macOS 12.0, *)
    func testValidateSignatureRS256Valid() async throws {
        let (oidc, _) = makeOIDCWithMockSession()
        oidc.jwksURI = jwksURL
        let (privKey, pubKey) = try makeRS256KeyPair()
        let jwt = try makeRS256SignedJWT(claims: ["sub": "user1"], kid: "rsa1", privateKey: privKey)
        let jwk = try makeRS256JWK(publicKey: pubKey, kid: "rsa1")
        MockURLProtocol.requestHandler = { _ in (self.makeJWKSResponse(), self.makeJWKSData(keys: [jwk])) }
        try await oidc.validateIDTokenSignature(jwt)
    }

    @available(macOS 12.0, *)
    func testValidateSignatureRS256WrongKey() async throws {
        let (oidc, _) = makeOIDCWithMockSession()
        oidc.jwksURI = jwksURL
        let (signingPriv, _) = try makeRS256KeyPair()
        let (_, verifyPub) = try makeRS256KeyPair() // separate key pair
        let jwt = try makeRS256SignedJWT(claims: ["sub": "user1"], kid: "rsa1", privateKey: signingPriv)
        let jwk = try makeRS256JWK(publicKey: verifyPub, kid: "rsa1") // wrong public key
        MockURLProtocol.requestHandler = { _ in (self.makeJWKSResponse(), self.makeJWKSData(keys: [jwk])) }
        do {
            try await oidc.validateIDTokenSignature(jwt)
            XCTFail("Expected invalidIDToken error for mismatched key")
        } catch OIDCLiteError.invalidIDToken(let reason) {
            XCTAssertTrue(reason.contains("RSA signature"), "Got: \(reason)")
        } catch {
            XCTFail("Unexpected error type: \(error)")
        }
    }

    @available(macOS 12.0, *)
    func testValidateSignatureSelectsKeyByKid() async throws {
        let (oidc, _) = makeOIDCWithMockSession()
        oidc.jwksURI = jwksURL
        let keyA = P256.Signing.PrivateKey()
        let keyB = P256.Signing.PrivateKey()
        // JWT is signed by keyB with kid "key-b"; JWKS has both keys
        let jwt = try makeES256SignedJWT(claims: ["sub": "user1"], kid: "key-b", privateKey: keyB)
        let jwkA = makeES256JWK(publicKey: keyA.publicKey, kid: "key-a")
        let jwkB = makeES256JWK(publicKey: keyB.publicKey, kid: "key-b")
        MockURLProtocol.requestHandler = { _ in (self.makeJWKSResponse(), self.makeJWKSData(keys: [jwkA, jwkB])) }
        // Should succeed: kid "key-b" selects jwkB, which matches the signing key
        try await oidc.validateIDTokenSignature(jwt)
    }

    @available(macOS 12.0, *)
    func testValidateSignatureNoKidUsesFirstKey() async throws {
        let (oidc, _) = makeOIDCWithMockSession()
        oidc.jwksURI = jwksURL
        let key = P256.Signing.PrivateKey()
        // JWT has no kid in header — should fall back to first JWKS key
        let jwt = try makeES256SignedJWT(claims: ["sub": "user1"], kid: nil, privateKey: key)
        let jwk = makeES256JWK(publicKey: key.publicKey, kid: "only-key")
        MockURLProtocol.requestHandler = { _ in (self.makeJWKSResponse(), self.makeJWKSData(keys: [jwk])) }
        try await oidc.validateIDTokenSignature(jwt)
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

    private func makeOIDCWithMockSession(secret: String? = nil) -> (OIDCLite, MockOIDCLiteDelegate) {
        let oidc = OIDCLite(discoveryURL: discoveryURL, clientID: clientID, clientSecret: secret, redirectURI: nil, scopes: nil)
        oidc.OIDCAuthEndpoint = authEndpoint
        oidc.OIDCTokenEndpoint = tokenEndpoint
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [MockURLProtocol.self]
        oidc.session = URLSession(configuration: config, delegate: nil, delegateQueue: nil)
        let delegate = MockOIDCLiteDelegate()
        oidc.delegate = delegate
        return (oidc, delegate)
    }

    private func waitForDelegate(_ delegate: MockOIDCLiteDelegate, block: () -> Void) {
        let exp = expectation(description: "delegate callback")
        delegate.onCompletion = { exp.fulfill() }
        block()
        wait(for: [exp], timeout: 2)
    }

    private func tokenSuccessData() -> Data {
        jsonData(["access_token": "at123", "token_type": "Bearer"])
    }

    private func makeHTTPResponse(status: Int = 200) -> HTTPURLResponse {
        HTTPURLResponse(url: URL(string: tokenEndpoint)!, statusCode: status, httpVersion: nil, headerFields: nil)!
    }

    /// Returns the raw (percent-encoded) form body string from a request.
    /// URLSession converts httpBody to httpBodyStream internally, so we check both.
    private func rawFormBody(from request: URLRequest?) -> String {
        guard let request = request else { return "" }
        if let body = request.httpBody {
            return String(data: body, encoding: .utf8) ?? ""
        }
        if let stream = request.httpBodyStream {
            stream.open()
            var data = Data()
            var buffer = [UInt8](repeating: 0, count: 4096)
            while stream.hasBytesAvailable {
                let count = stream.read(&buffer, maxLength: buffer.count)
                if count > 0 { data.append(contentsOf: buffer[..<count]) }
            }
            stream.close()
            return String(data: data, encoding: .utf8) ?? ""
        }
        return ""
    }

    /// Splits a form body into key → raw-encoded-value pairs (splits on first `=` per pair).
    private func parseFormBody(from request: URLRequest?) -> [String: String] {
        let str = rawFormBody(from: request)
        guard !str.isEmpty else { return [:] }
        var result: [String: String] = [:]
        for pair in str.components(separatedBy: "&") {
            guard let eqRange = pair.range(of: "=") else { continue }
            let key = String(pair[pair.startIndex..<eqRange.lowerBound])
            let value = String(pair[eqRange.upperBound...])
            result[key] = value
        }
        return result
    }

    // MARK: Signature-test helpers

    private func makeJWKSResponse() -> HTTPURLResponse {
        HTTPURLResponse(url: URL(string: jwksURL)!, statusCode: 200, httpVersion: nil, headerFields: nil)!
    }

    private func makeJWKSData(keys: [[String: Any]]) -> Data {
        try! JSONSerialization.data(withJSONObject: ["keys": keys])
    }

    private func makeES256JWK(publicKey: P256.Signing.PublicKey, kid: String) -> [String: Any] {
        let bytes = [UInt8](publicKey.x963Representation) // 0x04 || x(32) || y(32)
        return [
            "kty": "EC", "crv": "P-256", "kid": kid, "use": "sig", "alg": "ES256",
            "x": Data(bytes[1...32]).base64EncodedString().base64URLEncoded(),
            "y": Data(bytes[33...64]).base64EncodedString().base64URLEncoded(),
        ]
    }

    private func makeES256SignedJWT(claims: [String: Any], kid: String?,
                                    privateKey: P256.Signing.PrivateKey) throws -> String {
        var hdr: [String: Any] = ["alg": "ES256", "typ": "JWT"]
        if let kid = kid { hdr["kid"] = kid }
        let h = try! JSONSerialization.data(withJSONObject: hdr).base64EncodedString().base64URLEncoded()
        let p = try! JSONSerialization.data(withJSONObject: claims).base64EncodedString().base64URLEncoded()
        let input = "\(h).\(p)"
        let sig = try privateKey.signature(for: Data(input.utf8))
            .rawRepresentation.base64EncodedString().base64URLEncoded()
        return "\(input).\(sig)"
    }

    private func makeRS256KeyPair() throws -> (SecKey, SecKey) {
        let attrs: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits as String: 2048,
        ]
        var cfErr: Unmanaged<CFError>?
        guard let priv = SecKeyCreateRandomKey(attrs as CFDictionary, &cfErr),
              let pub = SecKeyCopyPublicKey(priv) else {
            throw cfErr!.takeRetainedValue()
        }
        return (priv, pub)
    }

    /// Extract the n and e components from a PKCS#1 RSA public key DER blob.
    private func parseRSAPublicKeyComponents(_ pubKey: SecKey) throws -> (n: Data, e: Data) {
        var cfErr: Unmanaged<CFError>?
        guard let der = SecKeyCopyExternalRepresentation(pubKey, &cfErr) as Data? else {
            throw cfErr!.takeRetainedValue()
        }
        var pos = 0
        let b = [UInt8](der)
        func readLen() -> Int {
            let first = Int(b[pos]); pos += 1
            guard first >= 0x80 else { return first }
            let nBytes = first & 0x7F; var len = 0
            for _ in 0..<nBytes { len = (len << 8) | Int(b[pos]); pos += 1 }
            return len
        }
        func readInt() -> Data {
            pos += 1 // INTEGER tag
            let len = readLen()
            var v = Data(b[pos..<pos + len]); pos += len
            if v.count > 1, v.first == 0x00 { v = Data(v.dropFirst()) } // strip DER sign byte
            return v
        }
        pos += 1; _ = readLen() // SEQUENCE tag + length
        return (readInt(), readInt())
    }

    private func makeRS256JWK(publicKey: SecKey, kid: String) throws -> [String: Any] {
        let (n, e) = try parseRSAPublicKeyComponents(publicKey)
        return [
            "kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256",
            "n": n.base64EncodedString().base64URLEncoded(),
            "e": e.base64EncodedString().base64URLEncoded(),
        ]
    }

    private func makeRS256SignedJWT(claims: [String: Any], kid: String?,
                                    privateKey: SecKey) throws -> String {
        var hdr: [String: Any] = ["alg": "RS256", "typ": "JWT"]
        if let kid = kid { hdr["kid"] = kid }
        let h = try! JSONSerialization.data(withJSONObject: hdr).base64EncodedString().base64URLEncoded()
        let p = try! JSONSerialization.data(withJSONObject: claims).base64EncodedString().base64URLEncoded()
        let input = "\(h).\(p)"
        var cfErr: Unmanaged<CFError>?
        guard let sig = SecKeyCreateSignature(
            privateKey, .rsaSignatureMessagePKCS1v15SHA256,
            Data(input.utf8) as CFData, &cfErr
        ) as Data? else { throw cfErr!.takeRetainedValue() }
        return "\(input).\(sig.base64EncodedString().base64URLEncoded())"
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

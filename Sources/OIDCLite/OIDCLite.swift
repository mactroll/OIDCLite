import Foundation
import CryptoKit
import WebKit

public enum OIDCLiteTokenResult {
    case success
    case passwordChanged
    case error(String)
}

@available(macOS 11.0, *)
public protocol OIDCLiteDelegate {
    func authFailure(message: String)
    func tokenResponse(tokens: OIDCLite.TokenResponse)
    func ropgSuccess(errorMessage: String)
}

@available(macOS 11.0, *)
public extension OIDCLiteDelegate {
    // Default no-op so existing implementations don't need to add ropgSuccess
    func ropgSuccess(errorMessage: String) {}
}

@propertyWrapper
struct IntConvertible: Decodable {
    var wrappedValue: Int
    init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if let intValue = try? container.decode(Int.self) {
            wrappedValue = intValue
        } else if let stringValue = try? container.decode(String.self), let intValue = Int(stringValue) {
            wrappedValue = intValue
        } else {
            // -1 signals decode failure; 0 would incorrectly mean "expired immediately"
            wrappedValue = -1
        }
    }
}

extension CharacterSet {
    static let urlQueryValueAllowed: CharacterSet = {
        // https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/encodeURIComponent
        // https://url.spec.whatwg.org/#concept-urlencoded
        // A-z0-9 and '*.-_' are allowed
        let generalDelimitersToEncode = ":#[]@?/"
        let subDelimitersToEncode = "!$&'()+,;=~"
        var allowed = CharacterSet.urlQueryAllowed
        allowed.remove(charactersIn: "\(generalDelimitersToEncode)\(subDelimitersToEncode)")
        // replace space with + afterwards
        allowed.insert(charactersIn: " ")
        return allowed
    }()
}

struct RefreshTokenResponse: Decodable {
    let accessToken, refreshToken, tokenType: String
    @IntConvertible var expiresIn: Int
    let expiresOn, extExpiresIn: String?

    enum CodingKeys: String, CodingKey {
        case accessToken = "access_token"
        case expiresIn = "expires_in"
        case expiresOn = "expires_on"
        case refreshToken = "refresh_token"
        case extExpiresIn = "ext_expires_in"
        case tokenType = "token_type"
    }
}

@available(macOS 11.0, *)
public class OIDCLite: NSObject {

    public struct TokenResponse {
        public var accessToken: String?
        public var idToken: String?
        public var refreshToken: String?
        public var expiresIn: Int?
        public var tokenType: String
        public var scope: String?
        public var jsonDict: [String: Any]?

        public init(
            accessToken: String? = nil,
            idToken: String? = nil,
            refreshToken: String? = nil,
            expiresIn: Int? = nil,
            tokenType: String = "bearer",
            scope: String? = nil,
            jsonDict: [String: Any]? = nil
        ) {
            self.accessToken = accessToken
            self.idToken = idToken
            self.refreshToken = refreshToken
            self.expiresIn = expiresIn
            self.tokenType = tokenType
            self.scope = scope
            self.jsonDict = jsonDict
        }
    }

    public let kRedirectURI = "oidclite://openID"
    public let kDefaultScopes = ["openid", "profile", "email", "offline_access"]

    // OpenID settings supplied at init
    public let discoveryURL: String
    public let redirectURI: String
    public let clientID: String
    public let scopes: [String]
    public let clientSecret: String?
    public let resource: String?
    public let additionalParameters: Dictionary<String, String>?

    // OpenID endpoints populated by getEndpoints()
    public var authorizationEndpoint: String?
    public var tokenEndpoint: String?

    // Aliases for backward compatibility
    public var OIDCAuthEndpoint: String? {
        get { authorizationEndpoint }
        set { authorizationEndpoint = newValue }
    }
    public var OIDCTokenEndpoint: String? {
        get { tokenEndpoint }
        set { tokenEndpoint = newValue }
    }

    // Regenerated on each createLoginURL() call; internal for testing
    private(set) var codeVerifier = ""

    var dataTask: URLSessionDataTask?
    // Single ephemeral session for all requests — no shared cookies, credentials, or cache
    var session = URLSession(configuration: .ephemeral, delegate: nil, delegateQueue: nil)

    public var delegate: OIDCLiteDelegate?

    private var state: String?
    // Internal (not private) so tests can read nonce after createLoginURL()
    var nonce: String?
    // Populated from the "issuer" field in the discovery document
    var discoveredIssuer: String?

    private let queryItemKeys = OIDCQueryItemKeys()

    private struct OIDCQueryItemKeys {
        let clientId = "client_id"
        let responseType = "response_type"
        let scope = "scope"
        let redirectUri = "redirect_uri"
        let state = "state"
        let codeChallengeMethod = "code_challenge_method"
        let codeChallenge = "code_challenge"
        let nonce = "nonce"
    }

    // OAuth/OIDC parameter names that additionalParameters must not override
    private static let reservedParameters: Set<String> = [
        "client_id", "response_type", "scope", "redirect_uri", "state",
        "code_challenge_method", "code_challenge", "nonce", "grant_type",
        "code", "code_verifier", "client_secret", "refresh_token",
    ]

    /// Create a new OIDCLite object
    /// - Parameters:
    ///   - discoveryURL: the full well-known openid-configuration URL
    ///   - clientID: the OpenID Connect client ID
    ///   - clientSecret: optional client secret
    ///   - redirectURI: optional redirect URI (non-http/https). Defaults to "oidclite://openID"
    ///   - scopes: optional custom scopes. Defaults to ["openid", "profile", "email", "offline_access"]
    ///   - additionalParameters: optional extra query parameters. Reserved OIDC names are silently ignored.
    public init(
        discoveryURL: String,
        clientID: String,
        clientSecret: String?,
        redirectURI: String?,
        scopes: [String]?,
        additionalParameters: Dictionary<String, String>? = nil
    ) {
        self.discoveryURL = discoveryURL
        self.clientID = clientID
        self.clientSecret = clientSecret
        self.redirectURI = redirectURI ?? "oidclite://openID"
        self.scopes = scopes ?? ["openid", "profile", "email", "offline_access"]
        self.additionalParameters = additionalParameters
        self.resource = nil
    }

    public init(
        discoveryURL: String,
        clientID: String,
        clientSecret: String?,
        redirectURI: String?,
        scopes: [String]?,
        additionalParameters: Dictionary<String, String>? = nil,
        resource: String?
    ) {
        self.discoveryURL = discoveryURL
        self.clientID = clientID
        self.clientSecret = clientSecret
        self.redirectURI = redirectURI ?? "oidclite://openID"
        self.scopes = scopes ?? ["openid", "profile", "email", "offline_access"]
        self.additionalParameters = additionalParameters
        self.resource = resource
    }

    /// Generates the login URL to pass to ASWebAuthenticationSession.
    /// A new code_verifier, state, and nonce are generated on every call.
    public func createLoginURL() -> URL? {
        state = UUID().uuidString
        let currentNonce = UUID().uuidString
        nonce = currentNonce
        codeVerifier = generateCodeVerifier()

        var queryItems: [URLQueryItem] = [
            URLQueryItem(name: queryItemKeys.clientId, value: clientID),
            URLQueryItem(name: queryItemKeys.responseType, value: "code"),
            URLQueryItem(name: queryItemKeys.scope, value: scopes.joined(separator: " ")),
        ]

        if let additionalParameters = additionalParameters {
            for (k, v) in additionalParameters where !OIDCLite.reservedParameters.contains(k) {
                queryItems.append(URLQueryItem(name: k, value: v))
            }
        }

        queryItems.append(URLQueryItem(name: queryItemKeys.redirectUri, value: redirectURI))
        queryItems.append(URLQueryItem(name: queryItemKeys.state, value: state))

        let hash = SHA256.hash(data: Data(codeVerifier.utf8))
        let challengeString = Data(hash).base64EncodedString().base64URLEncoded()
        queryItems.append(contentsOf: [
            URLQueryItem(name: queryItemKeys.codeChallengeMethod, value: "S256"),
            URLQueryItem(name: queryItemKeys.codeChallenge, value: challengeString),
        ])

        queryItems.append(URLQueryItem(name: queryItemKeys.nonce, value: currentNonce))

        guard let url = URL(string: authorizationEndpoint ?? "") else { return nil }
        var components = URLComponents(url: url, resolvingAgainstBaseURL: false)
        components?.queryItems = queryItems
        return components?.url
    }

    private func generateCodeVerifier() -> String {
        // 32 random bytes → 43-char base64url string, meeting RFC 7636 §4.1 minimum
        var randomBytes = [UInt8](repeating: 0, count: 32)
        _ = SecRandomCopyBytes(kSecRandomDefault, randomBytes.count, &randomBytes)
        return Data(randomBytes).base64EncodedString().base64URLEncoded()
    }

    func processOIDCResponse(_ data: Data) {
        do {
            guard let jsonResult = try JSONSerialization.jsonObject(with: data, options: .mutableContainers) as? [String: Any] else {
                delegate?.authFailure(message: "Unexpected response format")
                return
            }

            var tokenResponse = TokenResponse()

            tokenResponse.tokenType = jsonResult["token_type"] as? String ?? "bearer"

            if let expiresInt = jsonResult["expires_in"] as? Int {
                tokenResponse.expiresIn = expiresInt
            } else if let expiresStr = jsonResult["expires_in"] as? String, let expiresInt = Int(expiresStr) {
                tokenResponse.expiresIn = expiresInt
            }

            if let scope = jsonResult["scope"] as? String {
                tokenResponse.scope = scope
            }

            if let accessToken = jsonResult["access_token"] as? String {
                tokenResponse.accessToken = accessToken
            }
            if let refreshToken = jsonResult["refresh_token"] as? String {
                tokenResponse.refreshToken = refreshToken
            }
            if let idToken = jsonResult["id_token"] as? String {
                if let validationError = validateIDTokenClaims(idToken) {
                    delegate?.authFailure(message: validationError.errorDescription ?? "ID token validation failed")
                    return
                }
                tokenResponse.idToken = idToken
                nonce = nil // one-time use: clear after successful validation
            }
            tokenResponse.jsonDict = jsonResult

            delegate?.tokenResponse(tokens: tokenResponse)
        } catch {
            delegate?.authFailure(message: "Unable to decode response: \(data.base64EncodedString())")
        }
    }

    // NOTE: Signature verification (JWS/JWKS) is not performed. Claims validation
    // (exp, aud, iss, nonce) is enforced but the token's authenticity depends on TLS
    // to the token endpoint. Callers should add signature verification for full security.
    private func validateIDTokenClaims(_ idToken: String) -> OIDCLiteError? {
        let parts = idToken.components(separatedBy: ".")
        guard parts.count == 3 else {
            return .invalidIDToken("malformed JWT structure")
        }

        var base64 = parts[1]
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let remainder = base64.count % 4
        if remainder != 0 { base64 += String(repeating: "=", count: 4 - remainder) }

        guard let payloadData = Data(base64Encoded: base64),
              let claims = try? JSONSerialization.jsonObject(with: payloadData) as? [String: Any] else {
            return .invalidIDToken("unable to decode token claims")
        }

        if let expNumber = claims["exp"] as? NSNumber,
           Date().timeIntervalSince1970 > expNumber.doubleValue {
            return .invalidIDToken("token is expired")
        }

        let audMatches: Bool
        if let aud = claims["aud"] as? String {
            audMatches = aud == clientID
        } else if let auds = claims["aud"] as? [String] {
            audMatches = auds.contains(clientID)
        } else {
            audMatches = false
        }
        guard audMatches else {
            return .invalidIDToken("audience mismatch")
        }

        if let expectedIssuer = discoveredIssuer,
           let iss = claims["iss"] as? String,
           iss != expectedIssuer {
            return .invalidIDToken("issuer mismatch")
        }

        if let expectedNonce = nonce {
            guard let tokenNonce = claims["nonce"] as? String, tokenNonce == expectedNonce else {
                return .invalidIDToken("nonce mismatch — possible replay attack")
            }
        }

        return nil
    }

    // Form-encode a single value per application/x-www-form-urlencoded
    private func formEncode(_ value: String) -> String {
        (value.addingPercentEncoding(withAllowedCharacters: .urlQueryValueAllowed) ?? value)
            .replacingOccurrences(of: " ", with: "+")
    }

    private func buildFormBody(_ params: [(String, String)]) -> Data? {
        params.map { "\($0.0)=\(formEncode($0.1))" }.joined(separator: "&").data(using: .utf8)
    }

    // Percent-encode client credentials for HTTP Basic auth per RFC 6749 §2.3.1
    private func basicAuthHeader() -> String? {
        let encodedClientID = clientID.addingPercentEncoding(withAllowedCharacters: .urlQueryValueAllowed) ?? clientID
        let encodedSecret = clientSecret?.addingPercentEncoding(withAllowedCharacters: .urlQueryValueAllowed) ?? ""
        let credentials = encodedSecret.isEmpty ? encodedClientID : "\(encodedClientID):\(encodedSecret)"
        guard let data = credentials.data(using: .utf8) else { return nil }
        return "Basic \(data.base64EncodedString())"
    }

    /// Exchange an authorization code for tokens.
    /// When `basicAuth` is true, client credentials go in the Authorization header
    /// (RFC 6749 §2.3.1); otherwise they go in the POST body.
    public func getToken(code: String, basicAuth: Bool = false) {
        guard let path = tokenEndpoint else {
            delegate?.authFailure(message: "No token endpoint found")
            return
        }
        guard let tokenURL = URL(string: path) else {
            delegate?.authFailure(message: "Unable to make the token endpoint into a URL")
            return
        }

        var params: [(String, String)] = [
            ("grant_type", "authorization_code"),
            ("client_id", clientID),
            ("redirect_uri", redirectURI),
            ("code", code),
            ("code_verifier", codeVerifier),
        ]
        if let secret = clientSecret, !basicAuth {
            params.append(("client_secret", secret))
        }

        var req = URLRequest(url: tokenURL)
        req.httpMethod = "POST"
        req.httpBody = buildFormBody(params)
        req.allHTTPHeaderFields = [
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
        ]
        if basicAuth, let header = basicAuthHeader() {
            req.setValue(header, forHTTPHeaderField: "Authorization")
        }

        dataTask = session.dataTask(with: req) { data, response, error in
            if let error = error {
                self.delegate?.authFailure(message: error.localizedDescription)
                return
            }
            guard let httpResponse = response as? HTTPURLResponse else {
                self.delegate?.authFailure(message: "Invalid response from token endpoint")
                return
            }
            guard (200..<300).contains(httpResponse.statusCode) else {
                if let data = data,
                   let jsonResult = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
                    self.delegate?.authFailure(message: self.oauthErrorMessage(dict: jsonResult))
                } else {
                    self.delegate?.authFailure(message: "HTTP \(httpResponse.statusCode) from token endpoint")
                }
                return
            }
            guard let data = data else {
                self.delegate?.authFailure(message: "No data in token response")
                return
            }
            self.processOIDCResponse(data)
        }
        dataTask?.resume()
    }

    /// Async variant. When `basicAuth` is true, client credentials go in the
    /// Authorization header (RFC 6749 §2.3.1); otherwise they go in the POST body.
    @available(macOS 12.0, *)
    public func getToken(code: String, basicAuth: Bool = false) async throws {
        guard let path = tokenEndpoint else {
            delegate?.authFailure(message: "No token endpoint found")
            return
        }
        guard let tokenURL = URL(string: path) else {
            delegate?.authFailure(message: "Unable to make the token endpoint into a URL")
            return
        }

        var params: [(String, String)] = [
            ("grant_type", "authorization_code"),
            ("client_id", clientID),
            ("redirect_uri", redirectURI),
            ("code", code),
            ("code_verifier", codeVerifier),
        ]

        var req = URLRequest(url: tokenURL)
        req.httpMethod = "POST"
        req.allHTTPHeaderFields = [
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
        ]

        if basicAuth, let header = basicAuthHeader() {
            req.setValue(header, forHTTPHeaderField: "Authorization")
        } else if let secret = clientSecret {
            params.append(("client_secret", secret))
        }

        req.httpBody = buildFormBody(params)

        let (data, response) = try await session.data(for: req)
        guard let httpResponse = response as? HTTPURLResponse, (200..<300).contains(httpResponse.statusCode) else {
            if let jsonResult = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
                delegate?.authFailure(message: oauthErrorMessage(dict: jsonResult))
            } else {
                delegate?.authFailure(message: "HTTP error from token endpoint")
            }
            return
        }
        processOIDCResponse(data)
    }

    /// Fetch the authorization and token endpoints from the discovery document (blocking).
    public func getEndpoints() {
        guard let host = URL(string: discoveryURL) else {
            delegate?.authFailure(message: "Invalid discovery URL: \(discoveryURL)")
            return
        }

        var req = URLRequest(url: host)
        req.allHTTPHeaderFields = [
            "Accept": "application/json",
            "Cache-Control": "no-cache",
        ]
        req.httpMethod = "GET"

        let sema = DispatchSemaphore(value: 0)

        session.dataTask(with: req) { data, response, error in
            defer { sema.signal() }

            if let error = error {
                self.delegate?.authFailure(message: "Discovery failed: \(error.localizedDescription)")
                return
            }
            guard let httpResponse = response as? HTTPURLResponse,
                  (200..<300).contains(httpResponse.statusCode),
                  let data = data else {
                self.delegate?.authFailure(message: "Discovery request returned no valid response")
                return
            }
            if let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
                self.authorizationEndpoint = json["authorization_endpoint"] as? String ?? ""
                self.tokenEndpoint = json["token_endpoint"] as? String ?? ""
                self.discoveredIssuer = json["issuer"] as? String
            } else {
                self.delegate?.authFailure(message: "Unable to parse discovery endpoint")
            }
        }.resume()

        sema.wait()
    }

    /// Async variant — throws on network or parse failure.
    @available(macOS 12.0, *)
    public func getEndpoints() async throws {
        guard let host = URL(string: discoveryURL) else {
            throw OIDCLiteError.unableToLoadEndpoint
        }
        var req = URLRequest(url: host)
        req.allHTTPHeaderFields = [
            "Accept": "application/json",
            "Cache-Control": "no-cache",
        ]
        req.httpMethod = "GET"

        let (data, response) = try await session.data(for: req)
        guard let httpResponse = response as? HTTPURLResponse, (200..<300).contains(httpResponse.statusCode) else {
            throw OIDCLiteError.unableToLoadEndpoint
        }
        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw OIDCLiteError.unableToParseEndpoint
        }
        authorizationEndpoint = json["authorization_endpoint"] as? String ?? ""
        tokenEndpoint = json["token_endpoint"] as? String ?? ""
        discoveredIssuer = json["issuer"] as? String
    }

    /// Parse the redirect callback URL, validate state, and exchange the code for tokens.
    public func processResponseURL(url: URL) throws {
        guard url.absoluteString.hasPrefix(redirectURI) else {
            throw OIDCLiteError.invalidRedirectURI
        }

        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
              let queryItems = components.queryItems else {
            throw OIDCLiteError.unableToFindCode
        }

        let returnedState = queryItems.first(where: { $0.name == "state" })?.value
        guard let expectedState = state, returnedState == expectedState else {
            throw OIDCLiteError.invalidState
        }
        state = nil // one-time use

        guard let code = queryItems.first(where: { $0.name == "code" })?.value else {
            throw OIDCLiteError.unableToFindCode
        }

        getToken(code: code)
    }

    public func refreshTokens(_ refreshToken: String) {
        guard let path = tokenEndpoint else {
            delegate?.authFailure(message: "No token endpoint found")
            return
        }
        guard let tokenURL = URL(string: path) else {
            delegate?.authFailure(message: "Unable to make the token endpoint into a URL")
            return
        }

        var params: [(String, String)] = [
            ("grant_type", "refresh_token"),
            ("refresh_token", refreshToken),
            ("client_id", clientID),
        ]
        if let secret = clientSecret {
            params.append(("client_secret", secret))
        }

        var req = URLRequest(url: tokenURL)
        req.httpMethod = "POST"
        req.httpBody = buildFormBody(params)
        req.addValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        req.addValue("application/json", forHTTPHeaderField: "Accept")

        session.dataTask(with: req) { data, response, error in
            if let error = error {
                self.delegate?.authFailure(message: error.localizedDescription)
                return
            }
            guard let httpResponse = response as? HTTPURLResponse,
                  (200..<300).contains(httpResponse.statusCode) else {
                if let data = data,
                   let jsonResult = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
                    self.delegate?.authFailure(message: self.oauthErrorMessage(dict: jsonResult))
                } else {
                    self.delegate?.authFailure(message: "Token refresh failed")
                }
                return
            }
            guard let data = data else {
                self.delegate?.authFailure(message: "No data in refresh response")
                return
            }
            self.processOIDCResponse(data)
        }.resume()
    }

    /// ROPG (Resource Owner Password Grant). Client credentials are sent via Basic auth only
    /// per RFC 6749 §2.3 — use one authentication method per request.
    public func requestTokenWithROPG(username: String, password: String) {
        guard let urlString = tokenEndpoint, let url = URL(string: urlString) else {
            delegate?.authFailure(message: "Token endpoint not set")
            return
        }

        guard let header = basicAuthHeader() else {
            delegate?.authFailure(message: "Unable to encode credentials")
            return
        }

        var params: [(String, String)] = [
            ("grant_type", "password"),
            ("username", username),
            ("password", password),
            ("scope", scopes.joined(separator: " ")),
        ]
        if let resource = resource {
            params.append(("resource", resource))
        }

        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.httpBody = buildFormBody(params)
        req.setValue(header, forHTTPHeaderField: "Authorization")
        req.addValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        req.addValue("application/json", forHTTPHeaderField: "Accept")

        session.dataTask(with: req) { data, response, error in
            if let error = error {
                self.delegate?.authFailure(message: error.localizedDescription)
                return
            }
            guard let httpResponse = response as? HTTPURLResponse,
                  (200..<300).contains(httpResponse.statusCode) else {
                if let data = data,
                   let jsonResult = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
                    self.delegate?.authFailure(message: self.oauthErrorMessage(dict: jsonResult))
                } else {
                    self.delegate?.authFailure(message: "ROPG request failed")
                }
                return
            }
            guard let data = data else {
                self.delegate?.authFailure(message: "No data in ROPG response")
                return
            }
            self.processOIDCResponse(data)
        }.resume()
    }

    /// Async ROPG variant. `basicAuth` controls whether credentials go in the Authorization
    /// header (true, default) or the POST body (false). `overrideErrors` lists raw 4xx
    /// response bodies that should be surfaced as `ropgSuccess` rather than `authFailure`
    /// — useful for handling "password expired" responses as a distinct success path.
    @available(macOS 12.0, *)
    public func requestTokenWithROPG(
        username: String,
        password: String,
        basicAuth: Bool = true,
        overrideErrors: [String]? = nil
    ) async throws {
        guard let urlString = tokenEndpoint, let url = URL(string: urlString) else {
            delegate?.authFailure(message: "Token endpoint not set")
            return
        }

        var params: [(String, String)] = [
            ("grant_type", "password"),
            ("username", username),
            ("password", password),
            ("scope", scopes.joined(separator: " ")),
        ]
        if let resource = resource {
            params.append(("resource", resource))
        }

        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.allHTTPHeaderFields = [
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
        ]

        if basicAuth {
            guard let header = basicAuthHeader() else {
                delegate?.authFailure(message: "Unable to encode credentials")
                return
            }
            req.setValue(header, forHTTPHeaderField: "Authorization")
        } else {
            params.append(("client_id", clientID))
            if let secret = clientSecret {
                params.append(("client_secret", secret))
            }
        }

        req.httpBody = buildFormBody(params)

        let (data, response) = try await session.data(for: req)
        guard let httpResponse = response as? HTTPURLResponse else {
            delegate?.authFailure(message: "Invalid response from token endpoint")
            return
        }

        if (200..<300).contains(httpResponse.statusCode) {
            processOIDCResponse(data)
        } else if (400..<404).contains(httpResponse.statusCode),
                  let overrideErrors = overrideErrors,
                  let errorMessage = String(data: data, encoding: .utf8),
                  overrideErrors.contains(errorMessage) {
            delegate?.ropgSuccess(errorMessage: errorMessage)
        } else {
            delegate?.authFailure(message: String(data: data, encoding: .utf8) ?? "ROPG request failed")
        }
    }

    // Surface only the standard OAuth error fields (RFC 6749 §5.2) to avoid leaking
    // internal server details, PII, or correlation IDs from the IdP error body.
    private func oauthErrorMessage(dict: [String: Any]) -> String {
        let error = dict["error"] as? String ?? "unknown_error"
        var message = "OAuth error: \(error)"
        if let description = dict["error_description"] as? String {
            message += " — \(description)"
        }
        if let uri = dict["error_uri"] as? String {
            message += " (see: \(uri))"
        }
        return message
    }
}

// WKNavigationDelegate support for non-ASWebAuthenticationSession flows
@available(macOS 11.0, *)
extension OIDCLite: WKNavigationDelegate {

    public func webView(_ webView: WKWebView, didReceiveServerRedirectForProvisionalNavigation navigation: WKNavigation!) {
        guard let url = webView.url,
              url.absoluteString.hasPrefix(redirectURI),
              let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
              let queryItems = components.queryItems else {
            return
        }

        let returnedState = queryItems.first(where: { $0.name == "state" })?.value
        guard let expectedState = state, returnedState == expectedState else {
            delegate?.authFailure(message: OIDCLiteError.invalidState.errorDescription ?? "State mismatch")
            return
        }
        state = nil

        if let code = queryItems.first(where: { $0.name == "code" })?.value {
            getToken(code: code)
        }
    }
}

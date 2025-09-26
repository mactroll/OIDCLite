import Foundation
import CryptoKit
import WebKit
import os.log

public enum OIDCLiteTokenResult {
    case success
    case passwordChanged
    case error(String)
}

@available(macOS 11.0, *)
public protocol OIDCLiteDelegate {
    func tokenFailure(message: String)
    func tokenResponse(tokens: OIDCLite.TokenResponse)
}

@propertyWrapper
struct IntConvertible: Decodable {
    var wrappedValue: Int
    init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        wrappedValue = 0
        if let intValue = try? container.decode(Int.self) {
            wrappedValue = intValue
        } else if  let stringValue = try? container.decode(String.self), let intValue = Int(stringValue) {
            wrappedValue = intValue
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
    private static let logger = Logger(
        subsystem: Bundle.main.bundleIdentifier!,
        category: "oidc")
    
    public struct TokenResponse {
        public var accessToken: String?
        public var idToken: String?
        public var refreshToken: String?
        public var expiresIn: Int?
        public var tokenType: String
        public var scope: String?
        public var jsonDict: [String:Any]?
        
        public init(accessToken: String? = nil, idToken: String? = nil, refreshToken: String? = nil, expiresIn: Int? = nil, tokenType: String = "bearer", scope: String? = nil, jsonDict: [String : Any]? = nil) {
            self.accessToken = accessToken
            self.idToken = idToken
            self.refreshToken = refreshToken
            self.expiresIn = expiresIn
            self.tokenType = tokenType
            self.scope = scope
            self.jsonDict = jsonDict
        }
    }
    
    // Constants, in case nothing else is supplied
    
    public let kRedirectURI = "oidclite://openID"
    public let kDefaultScopes = ["openid", "profile", "email", "offline_access"]
    
    // OpenID settings, supplied on init()
    
    public let discoveryURL: String
    public let redirectURI: String
    public let clientID: String
    public let scopes: [String]
    public let clientSecret: String?
    public let resource:String?
    public let additionalParameters:Dictionary<String,String>?
    
    // OpenID endpoints, gathered from the discoveryURL
    
    public var OIDCAuthEndpoint: String?
    public var OIDCTokenEndpoint: String?
    
    // Used for PKCE, no need to be public
    
    var codeVerifier = (UUID.init().uuidString + UUID.init().uuidString)
    
    // URL Session bits, we make a new ephemeral session every time the class
    // is invoked to ensure no lingering cookies
    
    var dataTask: URLSessionDataTask?
    var session = URLSession(configuration: URLSessionConfiguration.ephemeral, delegate: nil, delegateQueue: nil)
    
    // delegate for callbacks
    
    public var delegate: OIDCLiteDelegate?
    
    private var state: String?
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
        let grantType = "grant_type"
        let username = "username"
        let password = "password"
        let resource = "resource"
    }
    
    /// Create a new OIDCLite object
    /// - Parameters:
    ///   - discoveryURL: the full well-known openid-configuration URL, e.g. https://my.idp.com/.well-known/openid-configuration
    ///   - clientID: the OpenID Connect client ID to be used
    ///   - clientSecret: optional OpenID Connect client secret
    ///   - redirectURI: optional redirect URI, can not be http or https. Defaults to "oidclite://openID" if nothing is supplied
    ///   - scopes: optional custom scopes to be used in the OpenID Connect request. If nothing is supplied ["openid", "profile", "email", "offline_access"] will be used
    ///
    public init(discoveryURL: String, clientID: String, clientSecret: String?, redirectURI: String?, scopes: [String]?, additionalParameters: Dictionary<String, String>? = nil, useROPG:Bool=false, ropgUsername:String?=nil, ropgPassword:String?=nil) {
        self.discoveryURL = discoveryURL
        self.clientID = clientID
        self.clientSecret = clientSecret
        self.redirectURI = redirectURI ?? "oidclite://openID"
        self.scopes = scopes ?? ["openid", "profile", "email", "offline_access"]
        self.additionalParameters = additionalParameters
        self.resource=nil
    }
    
    
    public init(discoveryURL: String, clientID: String, clientSecret: String?, redirectURI: String?, scopes: [String]?, additionalParameters: Dictionary<String, String>? = nil, useROPG:Bool=false, ropgUsername:String?=nil, ropgPassword:String?=nil, resource:String?=nil) {
        self.discoveryURL = discoveryURL
        self.clientID = clientID
        self.clientSecret = clientSecret
        self.redirectURI = redirectURI ?? "oidclite://openID"
        self.scopes = scopes ?? ["openid", "profile", "email", "offline_access"]
        self.additionalParameters = additionalParameters
        self.resource=resource
    }
    
    /// Generates the inital login URL which can be passed to ASWebAuthenticationSession
    /// - Returns: A URL to be used with ASWebAuthenticationSession
    public func createLoginURL() -> URL? {
        state = UUID().uuidString
        
        var queryItems: [URLQueryItem] = []
        
        let clientIdItem = URLQueryItem(name: queryItemKeys.clientId, value: clientID)
        queryItems.append(clientIdItem)
        
        let responseTypeItem: URLQueryItem
        let scopeItem: URLQueryItem
        
        responseTypeItem = URLQueryItem(name: queryItemKeys.responseType, value: "code")
        scopeItem = URLQueryItem(name: queryItemKeys.scope, value: scopes.joined(separator: " "))
        
        
        queryItems.append(contentsOf: [responseTypeItem, scopeItem])
        
        if let additionalParameters = additionalParameters {
            additionalParameters.forEach { k,v in
                
                let parameterItem = URLQueryItem(name: k, value: v)
                queryItems.append(contentsOf: [parameterItem])
                
            }
        }
        
        let redirectUriItem = URLQueryItem(name: queryItemKeys.redirectUri, value: redirectURI)
        queryItems.append(redirectUriItem)
        let stateItem = URLQueryItem(name: queryItemKeys.state, value: state)
        queryItems.append(stateItem)
        
        if let challengeData = codeVerifier.data(using: String.Encoding.ascii) {
            let codeChallengeMethodItem = URLQueryItem(name: queryItemKeys.codeChallengeMethod, value: "S256")
            let hash = SHA256.hash(data: challengeData)
            let challengeData = Data(hash)
            let challengeString = challengeData.base64EncodedString().base64URLEncoded()
            let codeChallengeItem = URLQueryItem(name: queryItemKeys.codeChallenge, value: challengeString)
            queryItems.append(contentsOf: [codeChallengeMethodItem, codeChallengeItem])
        }
        
        let nonceItem = URLQueryItem(name: queryItemKeys.nonce, value: UUID().uuidString)
        queryItems.append(nonceItem)
        
        guard let url = URL(string: OIDCAuthEndpoint ?? "") else {
            return nil
        }
        
        var urlComponents = URLComponents(url: url, resolvingAgainstBaseURL: false)
        urlComponents?.queryItems = queryItems
        return urlComponents?.url
    }


    func processOIDCResponse(_ data:Data) async throws -> TokenResponse {

        var tokenResponse = TokenResponse()

        let jsonResult = try JSONSerialization.jsonObject(with: data, options: JSONSerialization.ReadingOptions.mutableContainers) as? Dictionary<String, Any>

        if let tokenType = jsonResult?["token_type"] as? String {
            tokenResponse.tokenType = tokenType
        }

        if let expires = jsonResult?["expires_in"] as? Int {
            tokenResponse.expiresIn = expires
        }

        if let expires = jsonResult?["expires_in"] as? String {
            tokenResponse.expiresIn = Int(expires)!
        }

        if let scope = jsonResult?["scope"] as? String {
            tokenResponse.scope = scope
        }

        if let accessToken = jsonResult?["access_token"] as? String {
            tokenResponse.accessToken = accessToken
        }

        if let refreshToken = jsonResult?["refresh_token"] as? String {
            tokenResponse.refreshToken = refreshToken
        }

        if let idToken = jsonResult?["id_token"] as? String {
            tokenResponse.idToken = idToken
        }
        tokenResponse.jsonDict = jsonResult


        return tokenResponse
    }

    
    /// Turn a code, returned from a successful ASWebAuthenticationSession, into a token set
    /// - Parameter code: the code generated by a successful authentication
    public func getToken(code: String, basicAuth: Bool=false) async throws -> TokenResponse {
        guard let path = OIDCTokenEndpoint else {
            throw OIDCLiteError.authFailure("No token endpoint found")
        }
        
        guard let tokenURL = URL(string: path) else {
            throw OIDCLiteError.authFailure("Unable to make the token endpoint into a URL")
        }
        var body = "grant_type=authorization_code"
        var headers = [
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded"
        ]
        
        body.append("&client_id=" + clientID)
        
        if let secret = clientSecret {
            if basicAuth {
                headers["Authorization"] = "Basic " + ((clientID + ":" + secret).data(using: .utf8)?.base64EncodedString() ?? "")
            } else {
                body.append("&client_secret=" + secret )
            }
        }
        
        body.append("&redirect_uri=" + redirectURI.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed)!)
        let codeParam = "&code=" + code
        
        body.append(codeParam)
        body.append("&code_verifier=" + codeVerifier)
        
        var req = URLRequest(url: tokenURL)
        req.httpMethod = "POST"
        req.httpBody = body.data(using: .utf8)
        
        req.allHTTPHeaderFields = headers
        
        let (data, response) = try await URLSession.shared.data(for: req)
        
        if let response = response as? HTTPURLResponse,
           response.statusCode == 200 {
            let tokenResponse = try await self.processOIDCResponse(data)
            return tokenResponse

        } else {
            do {
                if let jsonResult = try JSONSerialization.jsonObject(with: data, options: JSONSerialization.ReadingOptions.mutableContainers) as? Dictionary<String, Any> {
                    throw OIDCLiteError.authFailure(self.prettyPrintInfo(dict: jsonResult))
                }
                throw OIDCLiteError.authFailure(response.debugDescription)

            }
        }
    }
    
    /// Function to parse the openid-configuration file into all of the requisite endpoints
    /// Function to async parse the openid-configuration file into all of the requisite endpoints
    public func getEndpoints() async throws {
        // make sure we can actually make a URL from the discoveryURL that we have
        guard let host = URL(string: discoveryURL) else { return }
        var req = URLRequest(url: host)
        
        let headers = [
            "Accept": "application/json",
            "Cache-Control": "no-cache",
        ]
        
        req.allHTTPHeaderFields = headers
        req.httpMethod = "GET"
        let (data, response) = try await session.data(for: req)
        if let response = response as? HTTPURLResponse,
           (200...228).contains(response.statusCode) {
            if let json = try JSONSerialization.jsonObject(with: data) as? [ String : Any] {
                self.OIDCAuthEndpoint = json["authorization_endpoint"] as? String ?? ""
                self.OIDCTokenEndpoint = json["token_endpoint"] as? String ?? ""
            } else {
                throw OIDCLiteError.unableToParseEndpoint
            }
        } else {
            throw OIDCLiteError.unableToLoadEndpoint
        }
    }
    
    /// Parse the response  from a redirect with a possible code in it.
    /// - Parameter url: redirect URL
    public func processResponseURL(url: URL) throws {
        if let query = url.query {
            let items = query.components(separatedBy: "&")
            for item in items {
                if item.starts(with: "code=") {
                    Task{
                        try await getToken(code: item.replacingOccurrences(of: "code=", with: ""))
                    }
                    return
                }
            }
        }
        throw OIDCLiteError.unableToFindCode
    }
    
    public func refreshTokens(_ refreshToken:String) async throws -> TokenResponse {

        var parameters = "grant_type=refresh_token&refresh_token=\(refreshToken)&client_id=\(clientID )"
        if let clientSecret = clientSecret {
            parameters.append("&client_secret=\(clientSecret)")
        }

        let postData =  parameters.data(using: .utf8)
        
        guard let path = OIDCTokenEndpoint else {
            throw OIDCLiteError.authFailure("No token endpoint found")
        }
        
        guard let tokenURL = URL(string: path) else {
            throw OIDCLiteError.authFailure("Unable to make the token endpoint into a URL")
        }
        
        var req = URLRequest(url: tokenURL)
        
        req.addValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        
        req.httpMethod = "POST"
        req.httpBody = postData
        
        let (data, _) = try await URLSession.shared.data(for: req)

        return try await self.processOIDCResponse(data)
    }

    
    public func requestTokenWithROPG(username: String, password: String, basicAuth: Bool, overrideErrors: [String]?) async throws -> TokenResponse? {
        guard let urlString = OIDCTokenEndpoint, let url = URL(string: urlString) else {
            throw OIDCLiteError.unableToLoadEndpoint

        }
        var req = URLRequest(url: url)
        
        var headers = [
            "Accept": "application/json",
            "Cache-Control": "no-cache",
            "Content-Type" : "application/x-www-form-urlencoded"
        ]

        let scopesURLString = scopes.joined(separator: " ").addingPercentEncoding(withAllowedCharacters: .urlQueryValueAllowed)?.replacingOccurrences(of: " ", with: "+")
        let encodedUsername = username.addingPercentEncoding(withAllowedCharacters: .urlQueryValueAllowed)?.replacingOccurrences(of: " ", with: "+")
        let encodedPassword = password.addingPercentEncoding(withAllowedCharacters: .urlQueryValueAllowed)?.replacingOccurrences(of: " ", with: "+")

        var reqComponents = URLComponents()
        var queryItems = [
            URLQueryItem(name: queryItemKeys.grantType, value: "password"),
            URLQueryItem(name: queryItemKeys.scope, value: scopesURLString),
            URLQueryItem(name: queryItemKeys.username, value: encodedUsername),
            URLQueryItem(name: queryItemKeys.password, value: encodedPassword)
        ]

        if let resource = resource, let encodedResource = resource.addingPercentEncoding(withAllowedCharacters: .urlQueryValueAllowed)?.replacingOccurrences(of: " ", with: "+"){

            queryItems.append(URLQueryItem(name: queryItemKeys.resource, value: encodedResource))

        }
        if !basicAuth {
            queryItems.append(URLQueryItem(name: "client_id", value: clientID))
            if let clientSecret = clientSecret {
                queryItems.append(URLQueryItem(name: "client_secret", value: clientSecret))
            }
        } else {
            var loginString = clientID
            if let clientSecret = clientSecret {
                loginString.append(":" + clientSecret)
            }
            if let data = loginString.data(using: .utf8) {
                headers["Authorization"] = "Basic " + data.base64EncodedString()
            } else {
                throw OIDCLiteError.authFailure("bad login info")
            }
        }
        
        reqComponents.queryItems = queryItems
        req.allHTTPHeaderFields = headers
        req.httpMethod = "POST"
        req.httpBody = reqComponents.query?.data(using: .utf8)
        
        let (data, response) = try await URLSession.shared.data(for: req)
        
        var responseCode = 0
        if let response = response as? HTTPURLResponse{
            responseCode = response.statusCode
        
        }
        if let response = response as? HTTPURLResponse,
           (200...228).contains(response.statusCode) {
            let tokenResponse =  try await self.processOIDCResponse(data)
            return tokenResponse
        } else if let response = response as? HTTPURLResponse,
                  (400...403).contains(response.statusCode),
                  let overrideErrors = overrideErrors,
                  let errorMessage = String(data: data, encoding: .utf8) {
            var success = false
            for i in overrideErrors {
                if errorMessage.contains(i) {
                    success = true
                    break
                }
            }
            if success {
                //no token to to give back but it isn't an error
                //because we got a 400 response with a match that says
                //it is ok. This is because ROPG can require MFA but
                //we don't care about anything except that the username/password
                //was good. So returning nil means no tokens but not an error
                // (we would throw if there was an error)
                return nil
            }
            else {
                throw OIDCLiteError.authFailure("Status code:\(responseCode), Did not match override:"+(String(data: data, encoding: .utf8) ?? "Unknown error"))
            }

        } else {
            throw OIDCLiteError.authFailure("Status code:\(responseCode), Not 400, no override, or bad error message:"+(String(data: data, encoding: .utf8) ?? "Unknown error"))
        }
    }
    
    private func prettyPrintInfo(dict: [String:Any]) -> String {
        
        var result = ""
        
        for item in dict {
            result.append("\(item.key):  ")
            result.append(String.init(describing: item.value))
            result.append("\n")
        }
        
        return result
    }
}

// Allow OIDCLite to be used as a WKNavigationDelegate
// This works for when you're not using ASWebAuthenticationSession

@available(macOS 11.0, *)
extension OIDCLite: WKNavigationDelegate {
    
    public func webView(_ webView: WKWebView, didReceiveServerRedirectForProvisionalNavigation navigation: WKNavigation!) {
        
        if (webView.url?.absoluteString.starts(with: (redirectURI))) ?? false {
            var code = ""
            let fullCommand = webView.url?.absoluteString ?? ""
            let pathParts = fullCommand.components(separatedBy: "&")
            for part in pathParts {
                if part.contains("code=") {
                    code = part.replacingOccurrences(of: redirectURI + "?" , with: "").replacingOccurrences(of: "code=", with: "")
                    Task{
                        do {
                           let tokenReponse = try await self.getToken(code: code)
                            delegate?.tokenResponse(tokens: tokenReponse)
                        }
                        catch {
                            delegate?.tokenFailure(message: "failure getting token")
                        }
                    }
                    return
                }
            }
        }
    }
}

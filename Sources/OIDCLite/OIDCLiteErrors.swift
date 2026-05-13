import Foundation

public enum OIDCLiteError: Error, Equatable {
    case unableToFindCode
    case unableToLoadEndpoint
    case unableToParseEndpoint
    case invalidState
    case invalidRedirectURI
    case invalidIDToken(String)
}

extension OIDCLiteError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .unableToFindCode:
            return "Unable to parse code from URL"
        case .unableToLoadEndpoint:
            return "Unable to load OIDC discovery endpoint"
        case .unableToParseEndpoint:
            return "Unable to parse OIDC discovery endpoint"
        case .invalidState:
            return "State parameter mismatch — possible CSRF attack"
        case .invalidRedirectURI:
            return "Redirect URI does not match the configured value"
        case .invalidIDToken(let reason):
            return "ID token validation failed: \(reason)"
        }
    }
}

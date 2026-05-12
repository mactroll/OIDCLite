import Foundation

public enum OIDCLiteError: Error, Equatable {
    case unableToFindCode
    case invalidState
    case invalidRedirectURI
    case invalidIDToken(String)
}

extension OIDCLiteError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .unableToFindCode:
            return "Unable to parse code from URL"
        case .invalidState:
            return "State parameter mismatch — possible CSRF attack"
        case .invalidRedirectURI:
            return "Redirect URI does not match the configured value"
        case .invalidIDToken(let reason):
            return "ID token validation failed: \(reason)"
        }
    }
}

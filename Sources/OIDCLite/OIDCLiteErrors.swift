//
//  File.swift
//  
//
//  Created by Joel Rennich on 1/23/22.
//

import Foundation

public enum OIDCLiteError: Error {
    case unableToFindCode, unableToLoadEndpoint, unableToParseEndpoint,tokenError(String),authFailure(String)
}

extension OIDCLiteError {
    public var errorDescription: String? {
        switch self {
        case .unableToFindCode:
            return "Unable to parse code from URL"
        case .unableToLoadEndpoint:
            return "Unable to load OIDC discovery endpoint"
        case .unableToParseEndpoint:
            return "Unable to parse OIDC discovery endpoint"
        case .authFailure:
            return "Authentication Failure"
        case .tokenError:
            return "Token Error"

        }
    }
}

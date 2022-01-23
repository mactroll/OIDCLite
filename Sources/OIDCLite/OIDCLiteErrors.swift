//
//  File.swift
//  
//
//  Created by Joel Rennich on 1/23/22.
//

import Foundation

public enum OIDCLiteError: Error {
    case unableToFindCode
}

extension OIDCLiteError {
    public var errorDescription: String? {
        switch self {
        case .unableToFindCode:
            return "Unable to parse code from URL"
        }
    }
}

//
//  File.swift
//  
//
//  Created by Joel Rennich on 1/23/22.
//

import Foundation

// need to import this to use ASWebAuthentication
import AuthenticationServices

class ASWebAuthManager: NSObject {
    // need to keep a strong reference to the authentication session
    var authSession: ASWebAuthenticationSession?
    
    func run(_ ephemeralSession: Bool=true) {
        
        let oidcLite = OIDCLite(discoveryURL: "https://oidc.example.com/.well-known/openid-configuration", clientID: "clientid", clientSecret: nil, redirectURI: "yourURI://oidc", scopes: nil)
        
        oidcLite.getEndpoints()
        
        if let url = oidcLite.createLoginURL() {
            
            // Note that the callbackURLScheme is your redirect URI without the path.
            // Also note that it can't be http/https
            authSession = ASWebAuthenticationSession.init(url: url, callbackURLScheme: "yourURI", completionHandler: { url, error in
                do {
                    try oidcLite.processResponseURL(url: url)
                } catch {
                    // Handle the error here
                    print(error)
                }
            })
            
            // set a presentation context provider
            authSession?.presentationContextProvider = self
            
            // set ephemeral session
            authSession?.prefersEphemeralWebBrowserSession = ephemeralSession
            
            // ensure the auth session can start
            if authSession?.canStart {
                
                // start the auth session on the Main loop
                RunLoop.main.perform {
                    self.authSession?.start()
                }
            } else {
                // Handle the error here
                print("Unable to start ASWebAuthenticationSession")
            }
        }
    }

}

// Allows this class to set a Presentation Context for the ASWebAuthentication Session

extension ASWebAuthManager: ASWebAuthenticationPresentationContextProviding {
    func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
        return ASPresentationAnchor()
    }
}

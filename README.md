# OIDCLite

While there are a few good Swift packages for Open ID Connect out there, most are /very/ heavyweight and can get quite complex. For projects that have rather modest needs of just confirming a user is valid, and perhaps acquring an OIDC token set for a subsequent operation, OIDCLite may be what you're looking for!

OIDCLite implements the basics of getting a token using Apple's ASWebAuthenticationSession so you have very little web things to deal with. OIDCLite fully supports PKCE and client secrets (if you must).

ASWebAuthenticationSession works REALLY well on iOS and should easily handle all of your needs. It blends in with your iOS app and it looks well put together. On the Mac... it's a bit of a different story, so try it out a few times.

`OIDCLite` will take a discovery URL, parse out the correct endpoints and provide you a URL to feed into `ASWebAuthenticationSession`. On a successful auth, you can pass the resultant code back into `OIDCLite` and have it get you a set of tokens.

`OIDCLite` fully supports PKCE (Proof Key for Code Exchange) in addition to client secrets.

By default `OIDCLite` will use `oidclite://OpenID` as the callback URI and `"openid", "profile", "email", "offline_access"` as the default scopes. You are, of course, free to change these to whatever you want.

This package supports macOS 10.15 and greater and iOS 14 and greater. It could probably work for older versions of macOS but you'd have to bail on CryptoKit and bring in CommonCrypto.

At some point `WKNavigationDelegate` support will be added to this so that you can use this package with WKWebViews in addition to ASWebAuthenticationSession. Although if you want to do that today... you can do the delegate yourself and pass the resultant code back into OIDCLite for processing.

<hr>

**Usage:**

Create a new OIDCLite object

`let oidcLite = OIDCLite(discoveryURL: "https://oidc.example.com/.well-known/openid-configuration", clientID: "clientid", clientSecret: nil, redirectURI: "yourURI://oidc", scopes: nil)`
        
Get the endpoints associated with the OIDC app

`oidcLite.getEndpoints()`

Once an ASWebAuthenticationSession has been created, you can process the redirect URI

`do {
        try oidcLite.processResponseURL(url: url)
    } catch {
        // Handle the error here
        print(error)
}`

A more detailed example can be found in the Examples folder.

<hr>

**Notes:**

- There's no support for any token lifecycle management here, this package is specifically to get a new token for authentication/identity purposes.

- There's no need to enable PKCE, as it's used with every operation regardless.

- Currently only a code grant flow is supported. For the purposes of authenticating an app this is the most preferred flow to use.

- This package has been succesfully tested with Okta, Azure, OneLogin and ORY Hydra OIDC servers. Confidence is high that this will work with any OIDC compliant service.

# OIDCLite

A simple class to allow you to use ASWebAuthenticationSession without having to mess with a lot of things.

`OIDCLite` will take a discovery URL, parse out the correct endpoints and provide you a URL to feed into `ASWebAuthenticationSession`. On a successful auth, you can pass the resultant code back into `OIDCLite` and have it get you a set of tokens.

`OIDCLite` fully supports PKCE (Proof Key for Code Exchange) in addition to client secrets.

By default `OIDCLite` will use `oidclite://OpenID` as the callback URI and 

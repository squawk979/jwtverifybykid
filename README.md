# jwtverifybykid

A library for HAProxy to verify JSON Web Tokens (JWT) against a JSON Web Key Set (JWKS)

I needed HAProxy to verify JWTs issued by AWS Cognito.  haproxytech/haproxy-lua-jwt provides a way of verifying against
a PEM file, but AWS Cognito supplies public keys used to sign JWTs in the JWKS format so there's a disconnect which this
library attempts to correct.

You could of course manually convert the JWT using inline tools such as https://8gwifi.org/jwkconvertfunctions.jsp but 
you'd have to manually update each time the keys changed.  AWS Cognito currently supplies 2 public keys in the JWKS.  
Although they don't seem to at the moment, it is possible they could start rotating the keys.  I therefore wanted 
something automatic.

This library decodes the JWKS file, stores an internal table of kid -> DER encoded public key mappings.  Each request
then has their associated JWT signature verified against this table (must be a signed by one of the keys in this table).

In haproxy.cfg global section you'll need something similar to:
  
  lua-load /usr/local/share/lua/5.3/jwtverifybykid.lua
  lua-load /usr/local/share/lua/5.3/jwtverify.lua
  setenv JWKS_JSON_PATH /etc/ssl/aws-cognito/jwks.json 
  
The order of the lua-loads is important (core.register_action seems to only work first time called?).  TODO: This could 
do with tidying up (eg only one lua-load), but I haven't had the time yet.

Also set up a cron job or similar to download the JWKS file from AWS (say) every week (it's not clear how frequently AWS
will change keys, I suspect very infrequently) and restart HAProxy at a convenient time (TODO: hitless reload possible?)

Consider this library experimental, it's the first time I've written any Lua code or extended HAProxy.  Any suggestions, 
fixes or extensions are welcome.
local json = require "json"
local base64 = require "base64"

JwtVerifyByKidConfig = {}

if not JwtVerifyByKidConfig.jwtKeys then
    JwtVerifyByKidConfig.jwtKeys = {}
end

local function log(msg)
    if config.debug then
        core.Debug(tostring(msg))
    end
end

-- jwtverifybykid() is a simple wrapper around jwtverify().  it decodes the JWT header to get the key id of the key
-- used to sign the token.  it looks up this key in its internal store and injects into jwtverify config.publicKey
-- before calling jwtverify() to verify the token.  note if the key isn't found it will set jwtverify
-- config.publicKey=nil and the verification will fail (which is what we want)
-- warning: this way of doing things is brittle as we depend on the internals of jwtverify and changes may break the
-- code (eg they change the name of config.publicKey variable)
function jwtverifybykid(txn)

 --  following code largely taken from https://github.com/haproxytech/haproxy-lua-jwt/blob/master/lib/jwtverify.lua
  local authorizationHeader = txn.sf:req_hdr("Authorization")
  local headerFields = core.tokenize(authorizationHeader, " .")

  if #headerFields ~= 4 then

    log("Improperly formatted Authorization header. Should be 'Bearer' followed by 3 token sections.")
      return nil
    end

    if headerFields[1] ~= 'Bearer' then
      log("Improperly formatted Authorization header. Missing 'Bearer' property.")
      return nil
    end

    local decodedHeader = json.decode(base64.decode(headerFields[2]))
    local kid = decodedHeader["kid"]
    config.publicKey = JwtVerifyByKidConfig.jwtKeys[kid]

    jwtverify(txn)

end

core.register_init(function()

  local jwksPath = os.getenv("JWKS_JSON_PATH")
  local jwksFile = assert(io.open(jwksPath, "rb"))
  local jwks = jwksFile:read("*all")
  jwksFile:close()

  local decodedJwks = json.decode(jwks)
  for i,key in ipairs(decodedJwks["keys"]) do

        local kid = key["kid"]
        local n = base64.decode(key["n"])
        local e = base64.decode(key["e"])

        -- lots of magic here, see https://stackoverflow.com/questions/18039401/how-can-i-transform-between-the-two-styles-of-public-key-format-one-begin-rsa
        -- for an excellent answer on DER formatted RSA public keys
        -- note we use DER format as jwtverify uses luaossl which accepts DER or PEM.  as above note this make our code
        -- brittle as again we are depending on the way the internals of jwtverify work which could be subject to change
        -- also note if using anything other than 2048 bit RSA signatures this code will require modification
        algorithmIdentifier = "\x30\x0D\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x01\x05\x00\x03\x82\x01\x0F\x00"
        rsaPublicKey = "\x30\x82\x01\x0A\x02\x82\x01\x01\x00" .. n .. "\x02\x03" .. e
        subjectPublicKeyInfo = "\x30\x82\x01\x22" .. algorithmIdentifier .. rsaPublicKey

        JwtVerifyByKidConfig.jwtKeys[kid] = subjectPublicKeyInfo

  end

end)

-- Called on a request.
core.register_action('jwtverifybykid', {'http-req'}, jwtverifybykid)

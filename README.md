![build status](https://api.travis-ci.com/ozzi-/JWT4B.svg?branch=master)
![licence](https://img.shields.io/github/license/mvetsch/JWT4B.svg)
![open issues](https://img.shields.io/github/issues/mvetsch/JWT4B.svg)


# JWT4B
JSON Web Tokens (JWT) support for the Burp Interception Proxy. JWT4B will let you manipulate a JWT on the fly, automate common attacks against JWT and decode it for you in the proxy history. JWT4B automagically detects JWTs in the form of 'Authorization Bearer' headers as well as customizable post body parameters and body content.

![Logo](https://i.imgur.com/SnrC5To.png)

# Screenshots
![Screenshot - Intercept View](https://i.imgur.com/VsbqoNL.png)

![Screenshot - Decode View](https://i.imgur.com/hsBNeE2.png)

![Screenshot - Suite Tab View](https://i.imgur.com/2HGOI27.png)

# Testing
The following url contains links to four pages which simulate a JWT being sent via XHR or as cookie.
 [https://oz-web.com/jwt/](https://oz-web.com/jwt/) 

# Configuration
A config file will be created under "%user.home%\.JWT4B\config.json" with the following content:
```
{
  "resetEditor": true,
  "highlightColor": "blue",
  "interceptComment": "Contains a JWT",
  "jwtKeywords": [
    "Authorization: Bearer",
    "Authorization: bearer",
    "authorization: Bearer",
    "authorization: bearer"
  ],
  "tokenKeywords": [
    "id_token",
    "ID_TOKEN",
    "access_token",
    "token"
  ],
  "cveAttackModePublicKey": "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuNCJ/1Tawe8DUIbQDxjRr+bVSoIdcOjJm5wskbMUjHopTWERzLo65yLPjCVcRudQ8DNJIs3yb+hzxi0b8uyKXK6nYTaxdwtRN61NMgI/ecNYw1A3nMLRJ4KetLCUqCehVV+OavJqwGXb0k4OhJu7VefLD9PxOQxLd/MxJLMTChqYYQWY069oNTB9uRaBRLwcEv3i8uiM3HAdx4di0FZLHN5yAt6Zq7TR53CUDSI74q/AH4zeuo+D/UscVTq2bInfJmN3NdA6XqPdjnu6DtT7VQZif+06sFXgnoieuUaeRE0Jn8ZY72hljToFZmsLUPPhTSzmFTgko4+MGnS29w1rbQIDAQAB",
  "cveAttackModePrivateKey": "MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQC40In/VNrB7wNQhtAPGNGv5tVKgh1w6MmbnCyRsxSMeilNYRHMujrnIs+MJVxG51DwM0kizfJv6HPGLRvy7IpcrqdhNrF3C1E3rU0yAj95w1jDUDecwtEngp60sJSoJ6FVX45q8mrAZdvSTg6Em7tV58sP0/E5DEt38zEksxMKGphhBZjTr2g1MH25FoFEvBwS/eLy6IzccB3Hh2LQVksc3nIC3pmrtNHncJQNIjvir8AfjN66j4P9SxxVOrZsid8mY3c10Dpeo92Oe7oO1PtVBmJ/7TqwVeCeiJ65Rp5ETQmfxljvaGWNOgVmawtQ8+FNLOYVOCSjj4wadLb3DWttAgMBAAECggEBALF/J2ngNxEW2loWf/Bf59NGoQakHF56VFZtEakFEvEvykcUuSGkojmmhyqUHyHBu0xWFSGmJfcwizCD1lnir6f/3aVR//LTHbeZa5Bh9FCfOrqqah7WREXr/zyOctdk6F+0HHW+SKRrr0k1yl+1qaABtFaJOR2PH1Qebs5OZjTGXvKtm5H7G4FeNPDjprCKB5vRiWPY5F3sRJOFp8TwkH5qbirgZh0KJiYuJMq9QtzjRHYjzALOSWldpqb8Xzcx7lHZbF8gNv3zeRJRJWTYATq8KVaZ3fs0mv9z37MPRC1AS9v4ylrwXsAviWvn21Q6E1jrxOxZfAhkoA2aLtFMr4kCgYEA68yc8mupFsRCwcfChauAExibU2lCmW1ImcWxGLQR0dVPyaEPlecwKxvdetWs7BPaxqogKppB71gsxXYASUntgwj1f7zXxo4rdSZv20B09eASo+I8qZpfDZWR1oM7HjXR40lWELtQhzD0QDQCUmQtCpVGgyheqPsrQntCeM5LEisCgYEAyKXD93Onevtg6K2GWmnIgCP8+PRvu9kYW+3yhN0BGzmJrVSlD6uw0SAsA7awd54Qs00gGcWoztDm7V+YHDcYy3oOzwip4Yw2S3kUPewupySLm1VrDBMdXVp1sQH/I5DE3B4c5OxgdCmiX+7hLkXBBjpOqbHS+2bsPs9qnO2M5McCgYAhj84G8yvuAaE+05/sRqzECwyQorrH+7YJrQm36mle5G2m1TXSsEU63Yx4n1EtiOXqwOwzJCGeX35/3HvN8qfLrsrCk65ipHmrAv2Ix3PeSzZb/SeFPGOrG07WqXcQpbhqEVYeq4qas20QdlaeQ4PlrbmLkYNnqdhObhzX9QTaYQKBgQDDa9/fpL8cIrWSKV/Ps3PaijKa7sfcd2coMiqgiPfI4lNbhDN3fcsrA2CbBVX+Su8NEzMOptrxA7nGu/JUmL0HgQvnTRLYYE2JWJYEcYJGvGtUkO8/xWY2RCKYkc9Dfn6dvJ57wFV5Dgvdz7V18e47+JIg6NcKkIXL7wxxZ1RwhQKBgQDd4nlMdJue4zA7hO2YGxUqX+ALVY6ikZ/SBOQIDrnI9aixwXYQ3t3Nwjim73/0uiLXLOpO92dBSym7GeSPYqWZhkyQ8C05tDyGvDI5b7bVmD1pxmnhG9sOktrkDVkOsYUnAhRwCgmuExkoeGWPvUt+85cmMpJfHHqbrb5FLqTeXQ=="
}
```
Changing the config requires a reload of the extension or BURP.
If you messed something up, just delete the file, it will be created again with the default values.
Note: If resetEditor is set to false, all options such as the re-singing and alg attack won't be reset for every new request. This might be useful when working in the repeater.

## Building your own version (with Eclipse)
1. Clone repository and create new Eclipse Java Project
2. Rightclick -> Configure -> Convert to Maven Project (downloading all required libraries)
3. Open Burp -> Extender -> APIs -> Save interface files -> Copy all files to JWT4B\src\burp
4. Export runnable fat JAR including libraries
5. Load the JAR in Burp through the Extender Tab -> Extensions -> Add (Good to know: CTRL+Click on a extension to reload it)

# Installation from BApp Store
This extension is available in the [BApp Store](https://portswigger.net/bappstore/f923cbf91698420890354c1d8958fee6).

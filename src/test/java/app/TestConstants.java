package app;

public class TestConstants {
    private TestConstants() {}

    public static final String METHOD_POST = "POST";
    public static final String METHOD_GET = "GET";

    public static final String REQUEST_TEMPLATE = """
                    ${METHOD:-GET} / HTTP/1.1\r
                    Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r
                    Accept-Language: en-US,en;q=0.5\r${ADD_HEADER:-}
                    Connection: close\r
                    Upgrade-Insecure-Requests: 1\r
                    \r
                    ${BODY:-}""";

    public static final String RESPONSE_TEMPLATE = """
                    HTTP/1.1 200 OK\r
                    Connection: Keep-Alive\r
                    Content-Type: text/html; charset=utf-8\r
                    Date: Wed, 10 Aug 2026 13:17:18 GMT\r${ADD_HEADER:-}
                    Server: Apache\r
                    \r
                    ${BODY:-}""";

    public static final String HS256_HEADER = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
    public static final String RS256_HEADER = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9";
    public static final String ES256_HEADER = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9";

    public static final String HS256_TOKEN = HS256_HEADER + ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ";
    public static final String HS256_BEAUTIFIED_TOKEN = HS256_HEADER + ".ewogICAic3ViIjoiMTIzNDU2Nzg5MCIsCiAgICJuYW1lIjoiSm9obiBEb2UiLAogICAiYWRtaW4iOnRydWUKfQ==.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ";
    public static final String HS256_TOKEN_2 = HS256_HEADER + ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6Ik1heCBNdXN0ZXJsaSIsImFkbWluIjp0cnVlfQ.9o7iXB3CEm8ciIJjc_yZPI49p7gSKX6zDddr3Gp5_hU";

    public static final String INVALID_HEADER_TOKEN = "eyJhbFbiOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjYZgeFONFh7HgQ";
    public static final String INVALID_HEADER_TOKEN_2 = "eyJhbFb___RANDOM_GARBAGE___ZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjYZgeFONFh7HgQ";
    public static final String INVALID_JSON_TOKEN = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDdIyfQ.GuoUe6tw79bJlbU1HU0ADX0pr0u2kf3r_4OdrDufSfQ";

    public static final String ES256_TOKEN = ES256_HEADER + ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.tyh-VfuzIxCyGYDlkBA7DfyjrqmSHu6pQ2hoZuFqUSLPNY2N0mpHb3nk5K17HWP_3cYHBw7AhHale5wky6-sVA";
    public static final String ES256_TOKEN_PUB = "-----BEGIN PUBLIC KEY-----MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEVs/o5+uQbTjL3chynL4wXgUg2R9q9UU8I5mEovUf86QZ7kOBIjJwqnzD1omageEHWwHdBO6B+dFabmdT9POxg==-----END PUBLIC KEY-----";

    // How To - CLI
    // echo -n '{"alg":"RS256","typ":"JWT"}' | base64 | sed s/\+/-/ | sed -E s/=+$//
    // echo -n '{"sub":"RS256inOTA","name":"John Doe"}' | base64 | sed s/\+/-/ | sed -E s/=+$//
    // openssl genrsa 2048 > jwtRSA256-private.pem
    // openssl rsa -in jwtRSA256-private.pem -pubout -outform PEM -out jwtRSA256-public.pem
    // echo -n "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJFUzI1NmluT1RBIiwibmFtZSI6IkpvaG4gRG9lIn0" | openssl dgst -sha256 -binary -sign jwtRSA256-private.pem  | openssl enc -base64 | tr -d '\n=' | tr -- '+/' '-_'
    public static final String RS256_TOKEN = RS256_HEADER + ".eyJzdWIiOiJSUzI1NmluT1RBIiwibmFtZSI6IkpvaG4gRG9lIn0.VnF6UI5CHgOcg4T-k04xWLy5DW_-BiH75ccS9EpF1KP-5QAPKSqhls558cSa2DBPj5yeoFql9DFZ9H_mthbtz_HSfQ1DEDviP5mVfx9c5scEE9ebCaz9a5fQ_2uS2urh6HFTV7kGzjRqKJOCmB6gqtgGsPioDtrWU4o9mlqCh7k3meKTk5AJjeULgts96H2or4P9SUPXmI4Bv97bfSoj8LD3aHgI5FeKBU1KBEDFgDwy3WSI-SBlkf-43EQZwMgIvSVgqY9VXkJnS2aeu76oRn1MzpJBxWVRQaBrTZRnB0CCt3JjtK1QtIGHkl-M9-bVviQ-XtVqp52-DPG2GZFpqQ";
    public static final String RS256_TOKEN_PUB = "-----BEGIN PUBLIC KEY-----MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAss7FTpt5OpOsNbb5bfmLZnn0D7NzkxqWn4s2r3ZkPcDFMLF4/31sJHCdNkiavFaM7w+DfuSXb0rSQ1Eh/WX9UPR/BN0a8BRzogfzcXOekt4DdnLZibkYtcBfg519tbNVu6geuYi4QbwXrtJUfEAGSbvC3F11aO/qtPHJiwC5XHLgA8kteVXNgto6IBmq2bio9kKMVtceNjxGm6PnH9jBWB3cnlHYipg6hZlqfkiw8sF7UosfTqGn4ibTNUxNVNQw3K5w9S9YylaNq5HOVeHX1egz0aokkXoNwjV/31kG+SQq7MKiJ/PlCPbzY5e3++chEAg6dMKI/FOmIJIwbw1rHwIDAQAB-----END PUBLIC KEY-----";
    public static final String RS256_TOKEN_PRIV = "-----BEGIN RSA PRIVATE KEY-----MIIEpAIBAAKCAQEAss7FTpt5OpOsNbb5bfmLZnn0D7NzkxqWn4s2r3ZkPcDFMLF4/31sJHCdNkiavFaM7w+DfuSXb0rSQ1Eh/WX9UPR/BN0a8BRzogfzcXOekt4DdnLZibkYtcBfg519tbNVu6geuYi4QbwXrtJUfEAGSbvC3F11aO/qtPHJiwC5XHLgA8kteVXNgto6IBmq2bio9kKMVtceNjxGm6PnH9jBWB3cnlHYipg6hZlqfkiw8sF7UosfTqGn4ibTNUxNVNQw3K5w9S9YylaNq5HOVeHX1egz0aokkXoNwjV/31kG+SQq7MKiJ/PlCPbzY5e3++chEAg6dMKI/FOmIJIwbw1rHwIDAQABAoIBAGBQ7QtoyCZ7gVn10+ofb62lp4gFnA3zVoteS/i8B0cUXaPbFVhaUTRXzPd+qIsm/AeSDbz+mWwDm7tTKsH6fDdtXDZce7Qy8A6pxcKpCxQFr0vQlcmQAPV2SHz3Cs4jad0JtHMwaEBQd1leRtAfFMQG9fIKDcKW6ZDKZUwQ+cgH2XRFbEYtEgrw/G5+ZCwk7lENJCRVIqOGZH5ZmSrIgeEJP1sZgt1+qMDzDSiVV0EHdH07n/5SNuPawazSCa8/NOcpSyADdD3mJ6NN1icS6NAYeFS2mEecx5Wh3Dsx01E1YpdcF2m+nvuWqIlIl8DX1P9cs8fg1qJbedUXE21hg1ECgYEA7AJug9W1Xqt/fFhHCNGaILznsGCKS5FHzm6zOOHX1cH9zjXLl0Ywvv2ioX0utlOk5KxPUwxKTUvg1cvZ0WsJWckgcfkvKxZ/mfT3E56Ocf8i/Ra1R7dF0V+quXE0uNHvfQGyGqU8d6BkDXE3TFFkxzdcoBx1uvk1K8HOxsNtSBsCgYEAwfP9eWOguLFN9C/KuUbeGsRNO1rfQcPL2F8T7W5NaBKZl5f85KuG7JaSA7s4aIpSuACTGYE6AS/4AiShadjf+HXqXcTxBUWJyFoa+Py7Qfb1a4sPOQUnz/CXukiBSHXWmNqVbuKODu6ARmFoHUd0KvK4fPilOnmCfgVbjMtd4U0CgYEA6ltHztYKMiXuhFVMxG8Os++hyj0zVvK+8Thv884f+32VQI2ey2rBwQYv1lhuaFMK7KBGbNtJdRQiAWtZsmCtemEEPOkKc6j1sLXWG79ZB84oulUwUjSludFbwKWvis+9Fs72QwtNziSQ9eA03y37+u74pW1dYvtQV1EuuaUaAX0CgYEAwBFjPkbO7peG3v5E/12SrWcgJFtFI9dFkqv1C/djaGCjAWBd7AWAw+IIDvHkVoJEkDrhcSxryKk8LMMhpbRDd8UtplZVaCcI3wN8Gn4M4rIxL6KyHIFif6V+W9dZT+yB6zTrLrfkfhzposjrVbNg8vcSg4+n8FRMSYf8tVzfRzECgYAcsA/jdZthHEN6P0FycbAL4ALcCK1AcBVwdyrPjOm3sJ+7j0AoIRT9UlIyZ8xhtC3EX2iURJKlENdAnPQYThR+kCWGJq4CHhod9RhJgXzDyYYxyGcLBKTBcXjzZpx0jSguk3UobMdXgL2kG70tfwt1Y1b201OJmOLTg8sFmTYJRA==-----END RSA PRIVATE KEY-----";
}
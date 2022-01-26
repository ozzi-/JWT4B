package app;

import app.tokenposition.Cookie;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static app.TestTokens.*;
import static java.util.Arrays.asList;
import static org.assertj.core.api.Assertions.assertThat;

class TestSetCookieDetection {

    @Test
    void testCookieReversedOrder() {
        List<String> headers = asList(
                "GET /jwt/response_cookie.php HTTP/1.1",
                "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language: en-US,en;q=0.5",
                "Set-Cookie: token=" + HS256_TOKEN,
                "Set-Cookie: test=best",
                "Connection: close",
                "Upgrade-Insecure-Requests: 1"
        );
        Cookie cookie = new Cookie(headers, "");
        String result = cookie.findJWTInHeaders(headers);
        assertThat(result).isEqualTo(HS256_TOKEN);
    }

    @Test
    void testCookieInvalidJWT() {
        List<String> headers = asList(
                "GET /jwt/response_cookie.php HTTP/1.1",
                "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language: en-US,en;q=0.5",
                "Set-Cookie: token=" + INVALID_TOKEN,
                "Connection: close",
                "Upgrade-Insecure-Requests: 1"
        );
        Cookie cookie = new Cookie(headers, "");
        String result = cookie.findJWTInHeaders(headers);
        assertThat(result).isNull();
    }

    @Test
    void testCookieNoJWT() {
        List<String> headers = asList(
                "GET /jwt/response_cookie.php HTTP/1.1",
                "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language: en-US,en;q=0.5",
                "Cookie: test=besst",
                "Connection: close",
                "Upgrade-Insecure-Requests: 1"
        );
        Cookie cookie = new Cookie(headers, "");
        String result = cookie.findJWTInHeaders(headers);
        assertThat(result).isNull();
    }

    @Test
    void testSetCookieGetTokenInvalid() {
        List<String> headers = asList(
                "GET /jwt/response_cookie.php HTTP/1.1",
                "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language: en-US,en;q=0.5",
                "Set-Cookie: token=" + INVALID_TOKEN,
                "Connection: close",
                "Upgrade-Insecure-Requests: 1"
        );
        Cookie cookie = new Cookie(headers, "");
        String result = cookie.findJWTInHeaders(headers);
        assertThat(result).isNull();
        assertThat(cookie.getToken()).isEmpty();
        assertThat(cookie.positionFound()).isFalse();
    }

    @Test
    void testSetCookieInvalid() {
        List<String> headers = asList(
                "GET /jwt/response_cookie.php HTTP/1.1",
                "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language: en-US,en;q=0.5",
                "Set-Cookie: token=" + INVALID_TOKEN,
                "Connection: close",
                "Upgrade-Insecure-Requests: 1"
        );
        Cookie cookie = new Cookie(headers, "");
        String result = cookie.findJWTInHeaders(headers);
        assertThat(result).isNull();
    }

    @Test
    void testSetCookieSemicolon() {
        List<String> headers = asList(
                "GET /jwt/response_cookie.php HTTP/1.1",
                "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language: en-US,en;q=0.5",
                "Set-Cookie: token=" + HS256_TOKEN + ";",
                "Connection: close",
                "Upgrade-Insecure-Requests: 1"
        );
        Cookie cookie = new Cookie(headers, "");
        String result = cookie.findJWTInHeaders(headers);
        assertThat(result).isEqualTo(HS256_TOKEN);
    }

    @Test
    void testSetCookieReplace() {
        List<String> headers = new ArrayList<>(
                asList(
                        "GET /jwt/response_cookie.php HTTP/1.1",
                        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                        "Accept-Language: en-US,en;q=0.5",
                        "Set-Cookie: token=" + HS256_TOKEN + ";",
                        "Connection: close",
                        "Upgrade-Insecure-Requests: 1"
                )
        );
        Cookie cookie = new Cookie(headers, "");
        String result = cookie.findJWTInHeaders(headers);
        assertThat(result).isEqualTo(HS256_TOKEN);
        List<String> replaces = cookie.replaceTokenInHeader(HS256_TOKEN_2, headers);
        Cookie cookieR = new Cookie(headers, "");
        String resultR = cookieR.findJWTInHeaders(replaces);

        assertThat(resultR).isEqualTo(HS256_TOKEN_2);
    }

    @Test
    void testSetCookie() {
        List<String> headers = asList(
                "GET /jwt/response_cookie.php HTTP/1.1",
                "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language: en-US,en;q=0.5",
                "Set-Cookie: token=" + HS256_TOKEN,
                "Connection: close",
                "Upgrade-Insecure-Requests: 1"
        );
        Cookie cookie = new Cookie(headers, "");
        String result = cookie.findJWTInHeaders(headers);
        assertThat(result).isEqualTo(HS256_TOKEN);
    }

    @Test
    void testSetCookieGetToken() {
        List<String> headers = asList(
                "GET /jwt/response_cookie.php HTTP/1.1",
                "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language: en-US,en;q=0.5",
                "Set-Cookie: token=" + HS256_TOKEN,
                "Connection: close",
                "Upgrade-Insecure-Requests: 1"
        );
        Cookie cookie = new Cookie(headers, "");
        @SuppressWarnings("unused")
        String result = cookie.findJWTInHeaders(headers);
        assertThat(cookie.getToken()).isEqualTo(HS256_TOKEN);
    }

    @Test
    void testSetCookieSecureFlag() {
        List<String> headers = asList(
                "GET /jwt/response_cookie.php HTTP/1.1",
                "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language: en-US,en;q=0.5",
                "Set-Cookie: token=" + HS256_TOKEN + "; expires=Thu, 01-Jan-1970 01:40:00 GMT; Max-Age=0; path=/; secure;",
                "Connection: close",
                "Upgrade-Insecure-Requests: 1"
        );
        Cookie cookie = new Cookie(headers, "");
        String result = cookie.findJWTInHeaders(headers);
        assertThat(result).isEqualTo(HS256_TOKEN);
        assertThat(cookie.hasSecureFlag()).isTrue();
    }

    @Test
    void testSetCookieHTTPOnlyFlag() {
        List<String> headers = asList(
                "GET /jwt/response_cookie.php HTTP/1.1",
                "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language: en-US,en;q=0.5",
                "Set-Cookie: token=" + HS256_TOKEN + "; expires=Thu, 01-Jan-1970 01:40:00 GMT; HttpOnly; Max-Age=0; path=/;",
                "Connection: close",
                "Upgrade-Insecure-Requests: 1"
        );
        Cookie cookie = new Cookie(headers, "");
        String result = cookie.findJWTInHeaders(headers);
        assertThat(result).isEqualTo(HS256_TOKEN);
        assertThat(cookie.hasHttpOnlyFlag()).isTrue();
    }

    @Test
    void testSetCookieBothFlags() {
        List<String> headers = asList(
                "GET /jwt/response_cookie.php HTTP/1.1",
                "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language: en-US,en;q=0.5",
                "Set-Cookie: token=" + HS256_TOKEN + "; expires=Thu, 01-Jan-1970 01:40:00 GMT; HttpOnly; Max-Age=0; secure; path=/;",
                "Connection: close",
                "Upgrade-Insecure-Requests: 1"
        );
        Cookie cookie = new Cookie(headers, "");
        String result = cookie.findJWTInHeaders(headers);
        assertThat(result).isEqualTo(HS256_TOKEN);
        assertThat(cookie.hasHttpOnlyFlag()).isTrue();
        assertThat(cookie.hasSecureFlag()).isTrue();
    }

    @Test
    void testSetCookieNoFlags() {
        List<String> headers = asList(
                "GET /jwt/response_cookie.php HTTP/1.1",
                "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language: en-US,en;q=0.5",
                "Set-Cookie: token=" + HS256_TOKEN + "; expires=Thu, 01-Jan-1970 01:40:00 GMT; Max-Age=0; path=/;",
                "Connection: close",
                "Upgrade-Insecure-Requests: 1"
        );
        Cookie cookie = new Cookie(headers, "");
        String result = cookie.findJWTInHeaders(headers);

        assertThat(result).isEqualTo(HS256_TOKEN);
        assertThat(cookie.hasHttpOnlyFlag()).isFalse();
        assertThat(cookie.hasSecureFlag()).isFalse();
    }
}

package app;

import static org.assertj.core.api.Assertions.assertThat;

import static java.util.Arrays.asList;

import static app.TestTokens.HS256_TOKEN;
import static app.TestTokens.INVALID_TOKEN;

import java.util.List;

import org.junit.jupiter.api.Test;

import app.tokenposition.AuthorizationBearerHeader;

class TestAuthorizationDetection {

  @Test
  void testAuthValid() {
    List<String> headers = asList("GET /jwt/response_cookie.php HTTP/1.1",
        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "Accept-Language: en-US,en;q=0.5",
        "Authorization: Bearer " + HS256_TOKEN, "Connection: close", "Upgrade-Insecure-Requests: 1");

    AuthorizationBearerHeader abh = new AuthorizationBearerHeader(headers, "");

    assertThat(abh.positionFound()).isTrue();
    assertThat(abh.getToken()).isEqualTo(HS256_TOKEN);
  }

  @Test
  void testAuthInvalid() {
    List<String> headers = asList("GET /jwt/response_cookie.php HTTP/1.1",
        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "Accept-Language: en-US,en;q=0.5",
        "Authorization: Bearer " + INVALID_TOKEN, "Connection: close", "Upgrade-Insecure-Requests: 1");

    AuthorizationBearerHeader abh = new AuthorizationBearerHeader(headers, "");

    assertThat(abh.positionFound()).isFalse();
  }

  @Test
  void testAuthInvalid2() {
    List<String> headers = asList("GET /jwt/response_cookie.php HTTP/1.1",
        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "Accept-Language: en-US,en;q=0.5",
        "Authorization: Bearer topsecret123456789!", "Connection: close", "Upgrade-Insecure-Requests: 1");

    AuthorizationBearerHeader abh = new AuthorizationBearerHeader(headers, "");

    assertThat(abh.positionFound()).isFalse();
  }
}

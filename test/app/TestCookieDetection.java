package app;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import app.tokenposition.Cookie;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import static app.TestTokens.HS256_TOKEN;
import static app.TestTokens.INVALID_TOKEN;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.params.provider.Arguments.arguments;

class TestCookieDetection {

	static Stream<Arguments> cookieHeaderAndToken() {
        return Stream.of(
                arguments("Cookie: token=" + HS256_TOKEN + "; othercookie=1234", HS256_TOKEN),
                arguments("Cookie: token=" + HS256_TOKEN + "; othercookie=1234;", HS256_TOKEN),
                arguments("Cookie: othercookie=1234; secondcookie=4321; token=" + HS256_TOKEN + ";", HS256_TOKEN),
                arguments("Cookie: emptycookie=; secondcookie=4321; token=" + HS256_TOKEN + ";", HS256_TOKEN),
                arguments("Cookie: secondcookie=4321; emptycookie=; token=" + HS256_TOKEN + ";", HS256_TOKEN),
                arguments("Cookie: secondcookie=4321; weirdcookie ; token=" + HS256_TOKEN + ";", HS256_TOKEN),
                arguments("Cookie: othercookie=1234; token=" + HS256_TOKEN, HS256_TOKEN),
                arguments("Cookie: token=" + HS256_TOKEN, HS256_TOKEN),
                arguments("Cookie: token=" + INVALID_TOKEN, null),
                arguments("Cookie: test=besst", null)
        );
	}

	@MethodSource("cookieHeaderAndToken")
	@ParameterizedTest(name = "{0}")
	void testCookie(String cookieHeader, String cookieToken) {
		List<String> headers = new ArrayList<>();
		headers.add("GET /jwt/response_cookie.php HTTP/1.1");
		headers.add("Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
		headers.add("Accept-Language: en-US,en;q=0.5");
		headers.add(cookieHeader);
		headers.add("Connection: close");
		headers.add("Upgrade-Insecure-Requests: 1");
		Cookie cookie = new Cookie(headers,"");

		String result = cookie.findJWTInHeaders(headers);

		assertThat(result).isEqualTo(cookieToken);
	}
}

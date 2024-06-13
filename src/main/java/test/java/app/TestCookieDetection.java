package app;

import java.util.Map;
import java.util.stream.Stream;

import app.tokenposition.Cookie;
import burp.api.montoya.MontoyaExtension;
import burp.api.montoya.http.message.requests.HttpRequest;
import org.apache.commons.text.StringSubstitutor;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import static app.TestConstants.*;
import static app.TestConstants.REQUEST_TEMPLATE;
import static burp.api.montoya.http.message.requests.HttpRequest.httpRequest;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.params.provider.Arguments.arguments;

@ExtendWith(MontoyaExtension.class)
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
                arguments("Cookie: token=" + INVALID_HEADER_TOKEN, null),
                arguments("Cookie: test=besst", null)
        );
	}

	@MethodSource("cookieHeaderAndToken")
	@ParameterizedTest(name = "{0}")
	void testCookie(String cookieHeader, String cookieToken) {
		Map<String, Object> params = Map.of(
				"ADD_HEADER", cookieHeader);

		HttpRequest httpRequest = httpRequest(StringSubstitutor.replace(REQUEST_TEMPLATE, params));

		Cookie cookie = new Cookie(httpRequest,true);

        assertThat(cookie.positionFound()).isEqualTo(cookieToken != null);
        assertThat(cookie.getToken()).isEqualTo((cookieToken != null) ? cookieToken : "");
	}
}

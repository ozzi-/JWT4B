package app;

import app.tokenposition.Cookie;
import burp.api.montoya.MontoyaExtension;
import burp.api.montoya.http.message.responses.HttpResponse;
import org.apache.commons.text.StringSubstitutor;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import java.util.Map;

import static app.TestConstants.*;
import static burp.api.montoya.http.message.responses.HttpResponse.httpResponse;
import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith(MontoyaExtension.class)
class TestSetCookieDetection {

	@Test
	void testCookieReversedOrder() {
		String cookieHeader = "Set-Cookie: token=" + HS256_TOKEN + "\r\n" + "Set-Cookie: test=best";

		Map<String, Object> params = Map.of("ADD_HEADER", cookieHeader);

		HttpResponse httpResponse = httpResponse(StringSubstitutor.replace(RESPONSE_TEMPLATE, params));

		Cookie cookie = new Cookie(httpResponse, false);

		assertThat(cookie.positionFound()).isTrue();
		assertThat(cookie.getToken()).isEqualTo(HS256_TOKEN);
	}

	@Test
	void testCookieInvalidJWT() {
		String cookieHeader = "Set-Cookie: token=" + INVALID_HEADER_TOKEN + "\r\n" + "Set-Cookie: test=best";

		Map<String, Object> params = Map.of("ADD_HEADER", cookieHeader);

		HttpResponse httpResponse = httpResponse(StringSubstitutor.replace(RESPONSE_TEMPLATE, params));

		Cookie cookie = new Cookie(httpResponse, false);

		assertThat(cookie.positionFound()).isFalse();
		assertThat(cookie.getToken()).isEmpty();
	}

	@Test
	void testSetCookieSemicolon() {
		String cookieHeader = "Set-Cookie: token=" + HS256_TOKEN + ";";

		Map<String, Object> params = Map.of("ADD_HEADER", cookieHeader);

		HttpResponse httpResponse = httpResponse(StringSubstitutor.replace(RESPONSE_TEMPLATE, params));

		Cookie cookie = new Cookie(httpResponse, false);

		assertThat(cookie.positionFound()).isTrue();
		assertThat(cookie.getToken()).isEqualTo(HS256_TOKEN);
	}

	@Test
	void testSetCookieReplace() {
		String cookieHeader1 = "Set-Cookie: token=" + HS256_TOKEN;

		Map<String, Object> params1 = Map.of("ADD_HEADER", cookieHeader1);

		HttpResponse httpResponse1 = httpResponse(StringSubstitutor.replace(RESPONSE_TEMPLATE, params1));

		Cookie cookie1 = new Cookie(httpResponse1, false);

		assertThat(cookie1.positionFound()).isTrue();
		assertThat(cookie1.getToken()).isEqualTo(HS256_TOKEN);

		cookie1.replaceToken(HS256_TOKEN_2);

		//
		String cookieHeader2 = "Set-Cookie: token=" + HS256_TOKEN_2;

		Map<String, Object> params2 = Map.of("ADD_HEADER", cookieHeader2);

		HttpResponse httpResponse2 = httpResponse(StringSubstitutor.replace(RESPONSE_TEMPLATE, params2));

		Cookie cookie2 = new Cookie(httpResponse2, false);

		assertThat(cookie2.positionFound()).isTrue();
		assertThat(cookie2.getToken()).isEqualTo(HS256_TOKEN_2);

		//
		assertThat(cookie1.getResponse().toString()).isEqualTo(cookie2.getResponse().toString());
	}

	@Test
	void testSetCookieSecureFlag() {
		String cookieHeader = "Set-Cookie: token=" + HS256_TOKEN + "; Secure;";

		Map<String, Object> params = Map.of("ADD_HEADER", cookieHeader);

		HttpResponse httpResponse = httpResponse(StringSubstitutor.replace(RESPONSE_TEMPLATE, params));

		Cookie cookie = new Cookie(httpResponse, false);

		assertThat(cookie.positionFound()).isTrue();
		assertThat(cookie.getToken()).isEqualTo(HS256_TOKEN);

		assertThat(cookie.getcFW().hasSecureFlag()).isTrue();
	}

	@Test
	void testSetCookieHTTPOnlyFlag() {
		String cookieHeader = "Set-Cookie: token=" + HS256_TOKEN + "; expires=Thu, 01-Jan-1970 01:40:00 GMT; HttpOnly; Max-Age=0; path=/;";

		Map<String, Object> params = Map.of("ADD_HEADER", cookieHeader);

		HttpResponse httpResponse = httpResponse(StringSubstitutor.replace(RESPONSE_TEMPLATE, params));

		Cookie cookie = new Cookie(httpResponse, false);

		assertThat(cookie.positionFound()).isTrue();
		assertThat(cookie.getToken()).isEqualTo(HS256_TOKEN);
		assertThat(cookie.getcFW().hasHttpOnlyFlag()).isTrue();
	}

	@Test
	void testSetCookieBothFlags() {
		String cookieHeader = "Set-Cookie: token=" + HS256_TOKEN + "; expires=Thu, 01-Jan-1970 01:40:00 GMT; HttpOnly; Max-Age=0; secure; path=/;";

		Map<String, Object> params = Map.of("ADD_HEADER", cookieHeader);

		HttpResponse httpResponse = httpResponse(StringSubstitutor.replace(RESPONSE_TEMPLATE, params));

		Cookie cookie = new Cookie(httpResponse, false);

		assertThat(cookie.positionFound()).isTrue();
		assertThat(cookie.getToken()).isEqualTo(HS256_TOKEN);
		assertThat(cookie.getcFW().hasHttpOnlyFlag()).isTrue();
		assertThat(cookie.getcFW().hasSecureFlag()).isTrue();
	}

	@Test
	void testSetCookieNoFlags() {
		String cookieHeader = "Set-Cookie: token=" + HS256_TOKEN + "; expires=Thu, 01-Jan-1970 01:40:00 GMT; Max-Age=0; path=/;";

		Map<String, Object> params = Map.of("ADD_HEADER", cookieHeader);

		HttpResponse httpResponse = httpResponse(StringSubstitutor.replace(RESPONSE_TEMPLATE, params));

		Cookie cookie = new Cookie(httpResponse, false);

		assertThat(cookie.positionFound()).isTrue();
		assertThat(cookie.getToken()).isEqualTo(HS256_TOKEN);
		assertThat(cookie.getcFW().hasHttpOnlyFlag()).isFalse();
		assertThat(cookie.getcFW().hasSecureFlag()).isFalse();
	}
}

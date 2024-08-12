package app;

import static burp.api.montoya.http.message.requests.HttpRequest.httpRequest;

import static app.TestConstants.*;

import static org.assertj.core.api.Assertions.assertThat;

import burp.api.montoya.MontoyaExtension;
import burp.api.montoya.http.message.requests.HttpRequest;

import app.tokenposition.AuthorizationBearerHeader;

import org.apache.commons.text.StringSubstitutor;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import java.util.Map;

@ExtendWith(MontoyaExtension.class)
class TestAuthorizationDetection {

	@Test
	void testAuthValid() {
		Map<String, Object> params = Map.of("ADD_HEADER", "Authorization: Bearer " + HS256_TOKEN);
		HttpRequest httpRequest = httpRequest(StringSubstitutor.replace(REQUEST_TEMPLATE, params));
		AuthorizationBearerHeader abh = new AuthorizationBearerHeader(httpRequest, true);

		assertThat(abh.positionFound()).isTrue();
		assertThat(abh.getToken()).isEqualTo(HS256_TOKEN);
	}
	
	@Test
	void testAuthValidLowerCase() {
		Map<String, Object> params = Map.of("ADD_HEADER", "authorization: bearer " + HS256_TOKEN);
		HttpRequest httpRequest = httpRequest(StringSubstitutor.replace(REQUEST_TEMPLATE, params));
		AuthorizationBearerHeader abh = new AuthorizationBearerHeader(httpRequest, true);

		assertThat(abh.positionFound()).isTrue();
		assertThat(abh.getToken()).isEqualTo(HS256_TOKEN);
	}
	
	@Test
	void testAuthValidNonAuthHeader() {
		Map<String, Object> params = Map.of("ADD_HEADER", "X-AUTH: bearer " + HS256_TOKEN);
		HttpRequest httpRequest = httpRequest(StringSubstitutor.replace(REQUEST_TEMPLATE, params));
		AuthorizationBearerHeader abh = new AuthorizationBearerHeader(httpRequest, true);

		assertThat(abh.positionFound()).isTrue();
		assertThat(abh.getToken()).isEqualTo(HS256_TOKEN);
	}
	
	@Test
	void testRandomHeaderWithoutBearer() {
		Map<String, Object> params = Map.of("ADD_HEADER", "Token: " + HS256_TOKEN);
		HttpRequest httpRequest = httpRequest(StringSubstitutor.replace(REQUEST_TEMPLATE, params));
		AuthorizationBearerHeader abh = new AuthorizationBearerHeader(httpRequest, true);

		assertThat(abh.positionFound()).isTrue();
		assertThat(abh.getToken()).isEqualTo(HS256_TOKEN);
	}

	@Test
	void testRandomHeaderWithoutBearerAndSpaces() {
		Map<String, Object> params = Map.of("ADD_HEADER", "Foo:     " + HS256_TOKEN+"   ");
		HttpRequest httpRequest = httpRequest(StringSubstitutor.replace(REQUEST_TEMPLATE, params));
		AuthorizationBearerHeader abh = new AuthorizationBearerHeader(httpRequest, true);

		assertThat(abh.positionFound()).isTrue();
		assertThat(abh.getToken()).isEqualTo(HS256_TOKEN);
	}

	@Test
	void testRandomHeaderWithInvalid() {
		Map<String, Object> params = Map.of("ADD_HEADER", "Token: " + INVALID_HEADER_TOKEN);
		HttpRequest httpRequest = httpRequest(StringSubstitutor.replace(REQUEST_TEMPLATE, params));
		AuthorizationBearerHeader abh = new AuthorizationBearerHeader(httpRequest, true);

		assertThat(abh.positionFound()).isFalse();
	}
	
	@Test
	void testAuthInvalid() {
		Map<String, Object> params = Map.of("ADD_HEADER", "Authorization: Bearer " + INVALID_HEADER_TOKEN);
		HttpRequest httpRequest = httpRequest(StringSubstitutor.replace(REQUEST_TEMPLATE, params));
		AuthorizationBearerHeader abh = new AuthorizationBearerHeader(httpRequest, true);

		assertThat(abh.positionFound()).isFalse();
	}

	@Test
	void testAuthInvalid2() {
		Map<String, Object> params = Map.of("ADD_HEADER", "Authorization: Bearer topsecret123456789!");
		HttpRequest httpRequest = httpRequest(StringSubstitutor.replace(REQUEST_TEMPLATE, params));
		AuthorizationBearerHeader abh = new AuthorizationBearerHeader(httpRequest, true);

		assertThat(abh.positionFound()).isFalse();
	}

}

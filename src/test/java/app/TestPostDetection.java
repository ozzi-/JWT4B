package app;


import app.tokenposition.PostBody;
import burp.api.montoya.MontoyaExtension;
import burp.api.montoya.http.message.requests.HttpRequest;
import org.apache.commons.text.StringSubstitutor;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.stream.Stream;

import static app.TestConstants.*;
import static burp.api.montoya.http.message.requests.HttpRequest.httpRequest;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.params.provider.Arguments.arguments;

@ExtendWith(MontoyaExtension.class)
class TestPostDetection {

	static Stream<Arguments> postDataAndDetectedTokens() {
		return Stream.of(
				arguments("test=best&token=" + HS256_TOKEN, HS256_TOKEN),
				arguments("token=" + HS256_TOKEN, HS256_TOKEN),
				arguments("token=" + HS256_TOKEN + "&test=best", HS256_TOKEN)
		);
	}

	@MethodSource("postDataAndDetectedTokens")
	@ParameterizedTest
	void testPostBody(String body, String bodyToken) {
		Map<String, Object> params = Map.of(
				"METHOD", METHOD_POST,
				"BODY", body);

		HttpRequest httpRequest = httpRequest(StringSubstitutor.replace(REQUEST_TEMPLATE, params));

		PostBody pb = new PostBody(httpRequest, true);

		assertThat(pb.positionFound()).isTrue();
		assertThat(pb.getToken()).isEqualTo(bodyToken);
	}


	static Stream<Arguments> postDataWhereNoTokenDetected() {
		return Stream.of(
				arguments("token=" + INVALID_HEADER_TOKEN + "&test=best"),
				arguments("")
		);
	}

	@MethodSource("postDataWhereNoTokenDetected")
	@ParameterizedTest
	void testPostBodyNoToken(String body) {
		Map<String, Object> params = Map.of(
				"METHOD", METHOD_POST,
				"BODY", body);

		HttpRequest httpRequest = httpRequest(StringSubstitutor.replace(REQUEST_TEMPLATE, params));

		PostBody pb = new PostBody(httpRequest, true);

		assertThat(pb.positionFound()).isFalse();
		assertThat(pb.getToken()).isEmpty();
	}

	@Test
	void testPostBodyReplace() {
		String body1 = "test=best&token=" + HS256_TOKEN;
		Map<String, Object> params1 = Map.of(
				"METHOD", METHOD_POST,
				"BODY", body1);

		HttpRequest httpRequest1 = httpRequest(StringSubstitutor.replace(REQUEST_TEMPLATE, params1));

		PostBody pb1 = new PostBody(httpRequest1, true);
		pb1.positionFound();

		pb1.replaceToken(HS256_TOKEN_2);

		//
		String body2 = "test=best&token=" + HS256_TOKEN_2;
		Map<String, Object> params2 = Map.of(
				"METHOD", METHOD_POST,
				"BODY", body2);

		HttpRequest httpRequest2 = httpRequest(StringSubstitutor.replace(REQUEST_TEMPLATE, params2));

		PostBody pb2 = new PostBody(httpRequest2, true);
		pb2.positionFound();

		//
		assertThat(pb1.getRequest().toString()).isEqualTo(pb2.getRequest().toString());
	}

}

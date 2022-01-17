package app;


import app.helpers.KeyValuePair;
import app.tokenposition.PostBody;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static app.TestTokens.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.params.provider.Arguments.arguments;

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
		PostBody pb = new PostBody(null, body);

		KeyValuePair result = pb.getJWTFromPostBody();

		assertThat(result.getValue()).isEqualTo(bodyToken);
	}

	static Stream<Arguments> postDataWhereNoTokenDetected() {
		return Stream.of(
				arguments("token=" + INVALID_TOKEN + "&test=best"),
				arguments("")
		);
	}

	@MethodSource("postDataWhereNoTokenDetected")
	@ParameterizedTest
	void testPostBody(String body) {
		PostBody pb = new PostBody(null, body);

		KeyValuePair result = pb.getJWTFromPostBody();

		assertThat(result).isNull();
	}

	@Test
	void testPostBodyReplace() {
		String body = "test=best&token=" + HS256_TOKEN;
		PostBody pb = new PostBody(null, body);

		String replaced = pb.replaceTokenImpl(HS256_TOKEN_2, body);
		PostBody pbR = new PostBody(null, replaced);
		KeyValuePair resultR = pbR.getJWTFromPostBody();

		assertThat(resultR.getValue()).isEqualTo(HS256_TOKEN_2);
	}
}

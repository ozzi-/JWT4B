package app;

import app.algorithm.AlgorithmWrapper;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import model.CustomJWToken;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static app.TestConstants.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.params.provider.Arguments.arguments;

class TestAlgorithmWrapper {

	static Stream<Arguments> tokensAndValidKeys() {
		return Stream.of(arguments("HS256", HS256_TOKEN, "secret"), arguments("ES256", ES256_TOKEN, ES256_TOKEN_PUB));
	}

	@MethodSource("tokensAndValidKeys")
	@ParameterizedTest(name = "{0}")
	void testTokenWithProperKey(String type, String token, String key) throws IllegalArgumentException {
		CustomJWToken tokenObj = new CustomJWToken(token);
		JWTVerifier verifier = JWT.require(AlgorithmWrapper.getVerifierAlgorithm(tokenObj.getAlgorithm(), key)).build();

		DecodedJWT test = verifier.verify(token);

		assertThat(test.getAlgorithm()).isEqualTo(type);
	}

	static Stream<Arguments> tokensAndInvalidKeys() {
		return Stream.of(arguments("HS256", HS256_TOKEN, "invalid"), arguments("ES256", ES256_TOKEN, ES256_TOKEN_PUB.replace("Z", "Y")));
	}

	@MethodSource("tokensAndInvalidKeys")
	@ParameterizedTest(name = "{0}")
	void testHSWithFalseKey(String type, String token, String key) throws IllegalArgumentException {
		CustomJWToken tokenObj = new CustomJWToken(token);
		JWTVerifier verifier = JWT.require(AlgorithmWrapper.getVerifierAlgorithm(tokenObj.getAlgorithm(), key)).build();

		assertThrows(SignatureVerificationException.class, () -> verifier.verify(token));
	}
}

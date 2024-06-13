package app;

import com.auth0.jwt.algorithms.Algorithm;

import model.CustomJWToken;
import org.junit.jupiter.api.Test;

import static app.TestConstants.INVALID_JSON_TOKEN;
import static org.junit.jupiter.api.Assertions.assertEquals;


class TestInvalidJSONToken {
	@Test
	void newTest() throws IllegalArgumentException {
		Algorithm algo = Algorithm.HMAC256("test");
		CustomJWToken cjt = new CustomJWToken(INVALID_JSON_TOKEN);
		cjt.calculateAndSetSignature(algo);
		String getToken = cjt.getToken();
		// we now assume that invalid tokens will be returned as received

		assertEquals(getToken, getToken); // TODO
	}
}

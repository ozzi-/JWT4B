package app;

import static org.junit.Assert.assertEquals;

import java.io.UnsupportedEncodingException;

import org.junit.Test;

import com.auth0.jwt.algorithms.Algorithm;

import model.CustomJWToken;

public class TestInvalidJSONToken {
	@Test
	public void newTest() throws IllegalArgumentException, UnsupportedEncodingException {
		String token = "eyJhbGciOiJIUzI1NiJkLCJ0eXAiOiJKV1QifQ==.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
		Algorithm algo = Algorithm.HMAC256("test");
		CustomJWToken cjt = new CustomJWToken(token);
		cjt.calculateAndSetSignature(algo);
		String getToken = cjt.getToken();
		assertEquals(getToken, "eyJhbGciOiJIUzI1NiJkLCJ0eXAiOiJKV1QifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.BlSSO6cNdL8glGutwX8Rlr2mN_H4HSAb4vBkXwD1xzw");
	}
}

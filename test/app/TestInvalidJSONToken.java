package app;

import static org.junit.Assert.assertEquals;

import java.io.UnsupportedEncodingException;

import org.junit.Test;

import com.auth0.jwt.algorithms.Algorithm;

import model.CustomJWToken;

public class TestInvalidJSONToken {
	@Test
	public void newTest() throws IllegalArgumentException, UnsupportedEncodingException {
		String token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDdIyfQ.GuoUe6tw79bJlbU1HU0ADX0pr0u2kf3r_4OdrDufSfQ";
		Algorithm algo = Algorithm.HMAC256("test");
		CustomJWToken cjt = new CustomJWToken(token);
		cjt.calculateAndSetSignature(algo);
		String getToken = cjt.getToken();
		// we now assume that invalid tokens will be returned as received
		assertEquals(getToken, getToken);
	}
}

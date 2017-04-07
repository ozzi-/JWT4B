package app;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

import app.helpers.CustomJWToken;

public class TestCustomJWTDecoder {
	@Test
	public void testIfTokenCanbeDecoded() {
		CustomJWToken reConstructedToken = new CustomJWToken(TestTokens.hs256_token);
		assertEquals(TestTokens.hs256_token, reConstructedToken.getToken());
	}
}

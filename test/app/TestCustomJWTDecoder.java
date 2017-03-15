package app;

import static org.junit.Assert.*;

import org.junit.Test;

import app.helpers.CustomJWTToken;

public class TestCustomJWTDecoder {
	@Test
	public void testIfTokenCanbeDecoded() {
		CustomJWTToken reConstructedToken = new CustomJWTToken(TestTokens.hs256_token);
		assertEquals(TestTokens.hs256_token, reConstructedToken.getToken());
	}
}

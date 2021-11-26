package app;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

import model.CustomJWToken;

public class TestCustomJWTDecoder {
	@Test
	public void testIfTokenCanbeDecoded() {
		CustomJWToken reConstructedToken = new CustomJWToken(TestTokens.hs256_token);
		assertEquals(TestTokens.hs256_token, reConstructedToken.getToken());
		assertEquals(true,reConstructedToken.isBuiltSuccessful());
	}

	@Test
	public void testBrokenToken() {
		CustomJWToken reConstructedToken = new CustomJWToken(TestTokens.invalid_token);
		assertEquals(false,reConstructedToken.isBuiltSuccessful());
	}


	@Test
	public void testIfTokenIsMinified(){
		CustomJWToken reConstructedToken = new CustomJWToken(TestTokens.hs256_token);
		assertEquals(true, reConstructedToken.isMinified());
	}

	@Test
	public void testIfTokenIsNotMinified(){
		CustomJWToken reConstructedToken = new CustomJWToken(TestTokens.hs256_beautified_token);
		assertEquals(false, reConstructedToken.isMinified());
	}
}
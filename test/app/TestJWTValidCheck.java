package app;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

import model.CustomJWToken;

public class TestJWTValidCheck {

	@Test
	public void testValid() {
		assertEquals(true, CustomJWToken.isValidJWT(TestTokens.hs256_token));
	}

	@Test
	public void testInValid() {
		assertEquals(false, CustomJWToken.isValidJWT(TestTokens.invalid_token));
	}

	@Test
	public void testInValid2() {
		assertEquals(false, CustomJWToken.isValidJWT(TestTokens.invalid_token_2));
	}

}

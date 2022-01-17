package app;

import model.CustomJWToken;
import org.junit.jupiter.api.Test;

import static app.TestTokens.*;
import static org.assertj.core.api.Assertions.assertThat;

class TestJWTValidCheck {

	@Test
	void testValid() {
		assertThat(CustomJWToken.isValidJWT(HS256_TOKEN)).isTrue();
	}

	@Test
	void testInValid() {
		assertThat(CustomJWToken.isValidJWT(INVALID_TOKEN)).isFalse();
	}

	@Test
	void testInValid2() {
		assertThat(CustomJWToken.isValidJWT(INVALID_TOKEN_2)).isFalse();
	}
}

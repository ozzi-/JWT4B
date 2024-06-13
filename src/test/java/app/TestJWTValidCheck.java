package app;

import model.CustomJWToken;
import org.junit.jupiter.api.Test;

import static app.TestConstants.*;
import static org.assertj.core.api.Assertions.assertThat;

class TestJWTValidCheck {

	@Test
	void testValid() {
		assertThat(CustomJWToken.isValidJWT(HS256_TOKEN)).isTrue();
	}

	@Test
	void testInvalidHeader() {
		assertThat(CustomJWToken.isValidJWT(INVALID_HEADER_TOKEN)).isFalse();
	}

	@Test
	void testInvalidHeader2() {
		assertThat(CustomJWToken.isValidJWT(INVALID_HEADER_TOKEN_2)).isFalse();
	}
}

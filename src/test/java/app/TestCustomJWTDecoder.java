package app;

import model.CustomJWToken;
import org.junit.jupiter.api.Test;

import static app.TestConstants.*;
import static org.assertj.core.api.Assertions.assertThat;

class TestCustomJWTDecoder {

	@Test
	void testIfTokenCanBeDecoded() {
		CustomJWToken reConstructedToken = new CustomJWToken(HS256_TOKEN);
		assertThat(reConstructedToken.getToken()).isEqualTo(HS256_TOKEN);
		assertThat(reConstructedToken.isBuiltSuccessful()).isTrue();
	}

	@Test
	void testBrokenToken() {
		CustomJWToken reConstructedToken = new CustomJWToken(INVALID_HEADER_TOKEN);
		assertThat(reConstructedToken.isBuiltSuccessful()).isFalse();
	}

	@Test
	void testIfTokenIsMinified() {
		CustomJWToken reConstructedToken = new CustomJWToken(HS256_TOKEN);
		assertThat(reConstructedToken.isMinified()).isTrue();
	}

	@Test
	void testIfTokenIsNotMinified() {
		CustomJWToken reConstructedToken = new CustomJWToken(HS256_BEAUTIFIED_TOKEN);
		assertThat(reConstructedToken.isMinified()).isFalse();
	}
}
package app;

import app.helpers.KeyHelper;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.security.Key;

import static org.assertj.core.api.Assertions.assertThat;

class TestKeyHelper {

	@ValueSource(strings = { "RSA", "EC" })
	@ParameterizedTest
	void testGetKeyInstanceWithNullPublicKey(String algorithm) {
		Key key = KeyHelper.getKeyInstance(null, algorithm, false);

		assertThat(key).isNull();
	}

	@ValueSource(strings = { "RSA", "EC" })
	@ParameterizedTest
	void testGetKeyInstanceWithNullPrivateKey(String algorithm) {
		Key key = KeyHelper.getKeyInstance(null, algorithm, true);

		assertThat(key).isNull();
	}
}

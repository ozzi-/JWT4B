package app.algorithm;

import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.AlgorithmMismatchException;
import com.auth0.jwt.interfaces.ECDSAKeyProvider;
import com.auth0.jwt.interfaces.RSAKeyProvider;

import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.stream.Stream;

import static app.helpers.KeyHelper.getKeyInstance;
import static app.algorithm.AlgorithmType.ASYMMETRIC;
import static app.algorithm.AlgorithmType.SYMMETRIC;

public enum AlgorithmWrapper {
	NONE("none", AlgorithmType.NONE),
	HS256("HS256", SYMMETRIC),
	HS384("HS384", SYMMETRIC),
	HS512("HS512", SYMMETRIC),
	RS256("RS256", ASYMMETRIC),
	RS384("RS384", ASYMMETRIC),
	RS512("RS512", ASYMMETRIC),
	ES256("ES256", ASYMMETRIC),
	ES256K("ES256K", ASYMMETRIC),
	ES384("ES384", ASYMMETRIC),
	ES512("ES512", ASYMMETRIC);

	private final String algorithmName;
	private final AlgorithmType type;

	AlgorithmWrapper(String algorithmName, AlgorithmType none) {
		this.algorithmName = algorithmName;
		this.type = none;
	}

	String algorithmName() {
		return algorithmName;
	}

	private Algorithm algorithm(byte[] key) {
		switch (this) {
			// HMAC with SHA-XXX
			case HS256:
				return Algorithm.HMAC256(key);
			case HS384:
				return Algorithm.HMAC384(key);
			case HS512:
				return Algorithm.HMAC512(key);

			// ECDSA with curve
			case ES256:
				return Algorithm.ECDSA256(new ECDSAKeyProviderImpl(new String(key)));
			case ES256K:
				return Algorithm.ECDSA256K(new ECDSAKeyProviderImpl(new String(key)));
			case ES384:
				return Algorithm.ECDSA384(new ECDSAKeyProviderImpl(new String(key)));
			case ES512:
				return Algorithm.ECDSA512(new ECDSAKeyProviderImpl(new String(key)));

			// RSASSA-PKCS1-v1_5 with SHA-XXX
			case RS256:
				return Algorithm.RSA256(new RSAKeyProviderImpl(new String(key)));
			case RS384:
				return Algorithm.RSA384(new RSAKeyProviderImpl(new String(key)));
			case RS512:
				return Algorithm.RSA512(new RSAKeyProviderImpl(new String(key)));

			case NONE:
			default:
				throwUnsupportedAlgo();
				return null;
		}
	}

	private Algorithm algorithm(String key) {
		switch (this) {
			// HMAC with SHA-XXX
			case HS256:
				return Algorithm.HMAC256(key);
			case HS384:
				return Algorithm.HMAC384(key);
			case HS512:
				return Algorithm.HMAC512(key);

			// ECDSA with curve
			case ES256:
				return Algorithm.ECDSA256(new ECDSAKeyProviderImpl(key));
			case ES256K:
				return Algorithm.ECDSA256K(new ECDSAKeyProviderImpl(key));
			case ES384:
				return Algorithm.ECDSA384(new ECDSAKeyProviderImpl(key));
			case ES512:
				return Algorithm.ECDSA512(new ECDSAKeyProviderImpl(key));

			// RSASSA-PKCS1-v1_5 with SHA-XXX
			case RS256:
				return Algorithm.RSA256(new RSAKeyProviderImpl(key));
			case RS384:
				return Algorithm.RSA384(new RSAKeyProviderImpl(key));
			case RS512:
				return Algorithm.RSA512(new RSAKeyProviderImpl(key));

			case NONE:
			default:
				throwUnsupportedAlgo();
				return null;
		}
	}
	public static Algorithm getVerifierAlgorithm(String algo, String key) {
		return withName(algo).algorithm(key);
	}

	public static Algorithm getSignerAlgorithm(String algo, String key) {
		return withName(algo).algorithm(key);
	}

	public static Algorithm getSignerAlgorithm(String algo, byte[] key) {
		return withName(algo).algorithm(key);
	}
	public static AlgorithmWrapper withName(String algorithm) {
		return Stream.of(AlgorithmWrapper.values())
				.filter(supportedAlgorithm -> algorithm.equals(supportedAlgorithm.algorithmName()))
				.findFirst()
				.orElseThrow(() -> new AlgorithmMismatchException("Unsupported algorithm '" + algorithm + "'"));
	}

	public static AlgorithmType getTypeOf(String algorithm) {
		return Stream.of(AlgorithmWrapper.values())
				.filter(supportedAlgorithm -> algorithm.equals(supportedAlgorithm.algorithmName()))
				.map(supportedAlgorithm -> supportedAlgorithm.type)
				.findFirst()
				.orElse(AlgorithmType.NONE);
	}

	private static class RSAKeyProviderImpl implements RSAKeyProvider {
		private final String key;

		private RSAKeyProviderImpl(String key) {
			this.key = key;
		}

		@Override
		public RSAPublicKey getPublicKeyById(String kid) {
			return (RSAPublicKey) getKeyInstance(key, "RSA", false);
		}

		@Override
		public RSAPrivateKey getPrivateKey() {
			return (RSAPrivateKey) getKeyInstance(key, "RSA", true);
		}

		@Override
		public String getPrivateKeyId() {
			return "id";
		}
	}

	private static class ECDSAKeyProviderImpl implements ECDSAKeyProvider {
		private final String key;

		private ECDSAKeyProviderImpl(String key) {
			this.key = key;
		}

		@Override
		public ECPublicKey getPublicKeyById(String kid) {
			return (ECPublicKey) getKeyInstance(key, "EC", false);
		}

		@Override
		public ECPrivateKey getPrivateKey() {
			return (ECPrivateKey) getKeyInstance(key, "EC", true);
		}

		@Override
		public String getPrivateKeyId() {
			return "id";
		}
	}
	
	private void throwUnsupportedAlgo() {
		throw new AlgorithmMismatchException("Unsupported algorithm '" + algorithmName + "'");
	}

}

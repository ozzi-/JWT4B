package app.algorithm;

import java.io.UnsupportedEncodingException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.RSAKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import com.auth0.jwt.algorithms.Algorithm;

import app.helpers.ConsoleOut;

public class AlgorithmLinker {

	public static final app.algorithm.AlgorithmWrapper none = new app.algorithm.AlgorithmWrapper("none", AlgorithmType.none);
	public static final app.algorithm.AlgorithmWrapper HS256 = new app.algorithm.AlgorithmWrapper("HS256", AlgorithmType.symmetric);
	public static final app.algorithm.AlgorithmWrapper HS384 = new app.algorithm.AlgorithmWrapper("HS384", AlgorithmType.symmetric);
	public static final app.algorithm.AlgorithmWrapper HS512 = new app.algorithm.AlgorithmWrapper("HS512", AlgorithmType.symmetric);
	public static final app.algorithm.AlgorithmWrapper RS256 = new app.algorithm.AlgorithmWrapper("RS256", AlgorithmType.asymmetric);
	public static final app.algorithm.AlgorithmWrapper RS384 = new app.algorithm.AlgorithmWrapper("RS384", AlgorithmType.asymmetric);
	public static final app.algorithm.AlgorithmWrapper RS512 = new app.algorithm.AlgorithmWrapper("RS512", AlgorithmType.asymmetric);
	public static final app.algorithm.AlgorithmWrapper ES256 = new app.algorithm.AlgorithmWrapper("ES256", AlgorithmType.asymmetric);
	public static final app.algorithm.AlgorithmWrapper ES384 = new app.algorithm.AlgorithmWrapper("ES384", AlgorithmType.asymmetric);
	public static final app.algorithm.AlgorithmWrapper ES512 = new app.algorithm.AlgorithmWrapper("ES512", AlgorithmType.asymmetric);

	private static final app.algorithm.AlgorithmWrapper[] supportedAlgorithms = {none, HS256, HS384, HS512, RS256, RS384, RS512, ES256, ES384, ES512};

	private static PublicKey generatePublicKeyFromString(String key, String algorithm) {
		PublicKey publicKey = null;
		key = key.replace("-----BEGIN PUBLIC KEY-----", "").replace("-----END PUBLIC KEY-----", "").replaceAll("\\s+", "").replaceAll("\\r+", "").replaceAll("\\n+", "");
		byte[] keyByteArray = Base64.getDecoder().decode(key);
		try {
			KeyFactory kf = KeyFactory.getInstance(algorithm);
			EncodedKeySpec keySpec = new X509EncodedKeySpec(keyByteArray);
			publicKey = kf.generatePublic(keySpec);
		} catch (NoSuchAlgorithmException e) {
			ConsoleOut.output("Could not reconstruct the public key, the given algorithm could not be found - " + e.getMessage());
		} catch (InvalidKeySpecException e) {
			ConsoleOut.output("Could not reconstruct the public key - " + e.getMessage());
		}
		return publicKey;
	}

	/**
	 * @param algo
	 * @param key  , either the secret or the private key
	 * @return the algorithm element from the library, if nothing matches the none algorithm element is returned
	 * @throws IllegalArgumentException
	 * @throws UnsupportedEncodingException
	 */
	public static Algorithm getAlgorithm(String algo, String key) throws IllegalArgumentException, UnsupportedEncodingException {
		if (algo.equals(HS256.getAlgorithm())) {
			return Algorithm.HMAC256(key);
		}
		if (algo.equals(HS384.getAlgorithm())) {
			return Algorithm.HMAC384(key);
		}
		if (algo.equals(HS512.getAlgorithm())) {
			return Algorithm.HMAC512(key);
		}
		if (algo.equals(ES256.getAlgorithm())) {
			return Algorithm.HMAC384(key); // TODO implement ES Algos properly
		}
		if (algo.equals(ES384.getAlgorithm())) {
			return Algorithm.HMAC384(key);
		}
		if (algo.equals(ES512.getAlgorithm())) {
			return Algorithm.HMAC384(key); // EOT -----------------------------
		}
		if (algo.equals(RS256.getAlgorithm())) {
			return Algorithm.RSA256((RSAKey) generatePublicKeyFromString(key, "RSA"));
		}
		if (algo.equals(RS384.getAlgorithm())) {
			return Algorithm.RSA384((RSAKey) generatePublicKeyFromString(key, "RSA"));
		}
		if (algo.equals(RS512.getAlgorithm())) {
			return Algorithm.RSA512((RSAKey) generatePublicKeyFromString(key, "RSA"));
		}

		return Algorithm.none();
	}
	
	/**
	 * @return gets the type (asymmetric, symmetric, none) of the provided @param algo
	 */
	public static String getTypeOf(String algorithm) {
		for (app.algorithm.AlgorithmWrapper supportedAlgorithm : supportedAlgorithms) {
			if (algorithm.equals(supportedAlgorithm.getAlgorithm())) {
				return supportedAlgorithm.getType();
			}
		}
		return AlgorithmType.none;
	}
	
	public static app.algorithm.AlgorithmWrapper[] getSupportedAlgorithms() {
		return supportedAlgorithms;
	}
}

package app.algorithm;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.StringReader;
import java.io.UnsupportedEncodingException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.interfaces.RSAKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

import com.auth0.jwt.algorithms.Algorithm;

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

	private static final app.algorithm.AlgorithmWrapper[] supportedAlgorithms = { none, HS256, HS384, HS512, RS256, RS384, RS512, ES256, ES384, ES512 };

	/**
	 * @return gets the type (asymmetric, symmetric, none) of the provided @param algo
	 */
	public static String getTypeOf(String algorithm){
		for (app.algorithm.AlgorithmWrapper supportedAlgorithm : supportedAlgorithms) {
			if(algorithm.equals(supportedAlgorithm.getAlgorithm())){
				return supportedAlgorithm.getType();
			}
		}
		return AlgorithmType.none;
	}

	private static PrivateKey generatePrivatKeyFromString(String privateKey) throws InvalidKeySpecException {
		StringBuilder pkcs8Lines = new StringBuilder();
		BufferedReader rdr = new BufferedReader(new StringReader(privateKey));
		String line;

		try {
			while ((line = rdr.readLine()) != null) {
				pkcs8Lines.append(line);
			}
		} catch (IOException e1) {
			e1.printStackTrace();
		}

		String pkcs8Pem = pkcs8Lines.toString();
		pkcs8Pem = pkcs8Pem.replace("-----BEGIN PRIVATE KEY-----", "");
		pkcs8Pem = pkcs8Pem.replace("-----END PRIVATE KEY-----", "");
		pkcs8Pem = pkcs8Pem.replaceAll("\\s+", "");

		byte[] pkcs8EncodedBytes = Base64.getDecoder().decode(pkcs8Pem);
		
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(pkcs8EncodedBytes);
		KeyFactory kf = null;
		try {
			kf = KeyFactory.getInstance("RSA");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace(); 
		}
		
		return kf.generatePrivate(keySpec);		
	}

	/**
	 * @param algo
	 * @param key , either the secret or the private key
	 * @return the algorithm element from the library, if nothing matches, algo null is returned
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
			return Algorithm.HMAC384(key);
		}
		if (algo.equals(ES384.getAlgorithm())) {
			return Algorithm.HMAC384(key);
		}
		if (algo.equals(ES512.getAlgorithm())) {
			return Algorithm.HMAC384(key);
		}
		try {
			if (algo.equals(RS256.getAlgorithm())) {
				return Algorithm.RSA256((RSAKey)generatePrivatKeyFromString(key));
			}
			if (algo.equals(RS384.getAlgorithm())) {
				return Algorithm.RSA384((RSAKey)generatePrivatKeyFromString(key));
			}
			if (algo.equals(RS512.getAlgorithm())) {
				return Algorithm.RSA512((RSAKey)generatePrivatKeyFromString(key));
			}
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		}

		return Algorithm.none();
	}
	
	public static app.algorithm.AlgorithmWrapper[] getSupportedAlgorithms() {
		return supportedAlgorithms;
	}
}

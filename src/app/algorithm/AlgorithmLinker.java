package app.algorithm;

import java.io.UnsupportedEncodingException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.RandomStringUtils;

import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.ECDSAKeyProvider;
import com.auth0.jwt.interfaces.RSAKeyProvider;

import app.helpers.Output;
import app.helpers.PublicKeyBroker;

public class AlgorithmLinker {
	
	public static final String[] keyBeginMarkers = new String[]{"-----BEGIN PUBLIC KEY-----","-----BEGIN CERTIFICATE-----"};
	public static final String[] keyEndMarkers = new String[]{"-----END PUBLIC KEY-----","-----END CERTIFICATE-----"};
	
	public static final app.algorithm.AlgorithmWrapper none = 
			new app.algorithm.AlgorithmWrapper("none",AlgorithmType.none);
	public static final app.algorithm.AlgorithmWrapper HS256 = 
			new app.algorithm.AlgorithmWrapper("HS256",AlgorithmType.symmetric);
	public static final app.algorithm.AlgorithmWrapper HS384 =
			new app.algorithm.AlgorithmWrapper("HS384",AlgorithmType.symmetric);
	public static final app.algorithm.AlgorithmWrapper HS512 = 
			new app.algorithm.AlgorithmWrapper("HS512",AlgorithmType.symmetric);
	public static final app.algorithm.AlgorithmWrapper RS256 = 
			new app.algorithm.AlgorithmWrapper("RS256",AlgorithmType.asymmetric);
	public static final app.algorithm.AlgorithmWrapper RS384 = 
			new app.algorithm.AlgorithmWrapper("RS384",AlgorithmType.asymmetric);
	public static final app.algorithm.AlgorithmWrapper RS512 = 
			new app.algorithm.AlgorithmWrapper("RS512",AlgorithmType.asymmetric);
	public static final app.algorithm.AlgorithmWrapper ES256 = 
			new app.algorithm.AlgorithmWrapper("ES256",AlgorithmType.asymmetric);
	public static final app.algorithm.AlgorithmWrapper ES256K = 
			new app.algorithm.AlgorithmWrapper("ES256K",AlgorithmType.asymmetric);
	public static final app.algorithm.AlgorithmWrapper ES384 = 
			new app.algorithm.AlgorithmWrapper("ES384",AlgorithmType.asymmetric);
	public static final app.algorithm.AlgorithmWrapper ES512 = 
			new app.algorithm.AlgorithmWrapper("ES512",AlgorithmType.asymmetric);

	private static final app.algorithm.AlgorithmWrapper[] supportedAlgorithms = { 
			none, HS256, HS384, HS512, RS256, RS384, RS512, ES256, ES256K, ES384, ES512 };

	private static PublicKey generatePublicKeyFromString(String key, String algorithm) {
		PublicKey publicKey = null;
		if(key.length()>1){
			key = cleanKey(key);
			byte[] keyByteArray = java.util.Base64.getDecoder().decode(key);
			try {
				KeyFactory kf = KeyFactory.getInstance(algorithm);
				EncodedKeySpec keySpec = new X509EncodedKeySpec(keyByteArray);
				publicKey = kf.generatePublic(keySpec);
			} catch (Exception e) {
				Output.outputError(e.getMessage());
			}
		}
		return publicKey;
	}

	public static String cleanKey(String key) {
		for (String keyBeginMarker : keyBeginMarkers) {
			key = key.replace(keyBeginMarker, "");		
		}
		for (String keyEndMarker : keyEndMarkers) {
			key = key.replace(keyEndMarker, "");
		}
		key = key.replaceAll("\\s+", "").replaceAll("\\r+", "").replaceAll("\\n+", "");			

		return key;
	}
	
	private static PrivateKey generatePrivateKeyFromString(String key, String algorithm) {
		PrivateKey privateKey = null;
		if(key.length()>1){
			key = cleanKey(key);
			try {
				byte[] keyByteArray = Base64.decodeBase64(key);
				KeyFactory kf = KeyFactory.getInstance(algorithm);
				EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyByteArray);
				privateKey = kf.generatePrivate(keySpec);
			} catch (Exception e) {
				Output.outputError("Error generating private key with input string '"+key+"' and algorithm '"+algorithm+"' - "+e.getMessage()+" - ");
			}
		}
		return privateKey;
	}
	/**
	 * @param algo
	 * @param key - either the secret or the private key
	 * @return the algorithm element from the library, if nothing matches the
	 *         none algorithm element is returned
	 * @throws IllegalArgumentException
	 * @throws UnsupportedEncodingException
	 */
	public static Algorithm getVerifierAlgorithm(String algo, String key) throws UnsupportedEncodingException {
		return getAlgorithm(algo, key);
	}

	public static Algorithm getSignerAlgorithm(String algo, String key) throws UnsupportedEncodingException {
		return getAlgorithm(algo, key);
	}

	private static Algorithm getAlgorithm(String algo, String key) throws IllegalArgumentException, UnsupportedEncodingException {
			
		// HMAC with SHA-XXX
		if (algo.equals(HS256.getAlgorithm())) {
			return Algorithm.HMAC256(key);
		}
		if (algo.equals(HS384.getAlgorithm())) {
			return Algorithm.HMAC384(key);
		}
		if (algo.equals(HS512.getAlgorithm())) {
			return Algorithm.HMAC512(key);
		}
			
		// ECDSA with curve
		ECDSAKeyProvider keyProvider = new ECDSAKeyProvider() {
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
		};
		
		if (algo.equals(ES256.getAlgorithm())) {
			return Algorithm.ECDSA256(keyProvider);
		}
		if (algo.equals(ES256K.getAlgorithm())) {
			return Algorithm.ECDSA256K(keyProvider);
		}
		if (algo.equals(ES384.getAlgorithm())) {
			return Algorithm.ECDSA384(keyProvider);
		}
		if (algo.equals(ES512.getAlgorithm())) {
			return Algorithm.ECDSA512(keyProvider);
		}
		
		// RSASSA-PKCS1-v1_5 with SHA-XXX
		RSAKeyProvider keyProviderRSA = new RSAKeyProvider() {
		    @Override
		    public RSAPublicKey getPublicKeyById(String kid) {
		        return (RSAPublicKey) getKeyInstance(key, "EC", false);
		    }

		    @Override
		    public RSAPrivateKey getPrivateKey() {
		        return (RSAPrivateKey) getKeyInstance(key, "EC", true);
		    }

		    @Override
		    public String getPrivateKeyId() {
		        return "id";
		    }
		};
		
		if (algo.equals(RS256.getAlgorithm())) {
			return Algorithm.RSA256(keyProviderRSA);
		}
		if (algo.equals(RS384.getAlgorithm())) {
			return Algorithm.RSA384(keyProviderRSA);
		}
		if (algo.equals(RS512.getAlgorithm())) {
			return Algorithm.RSA512(keyProviderRSA);
		}

		return Algorithm.none();
	}

	public static Key getKeyInstance(String key, String algorithm, boolean isPrivate) {
		return isPrivate? generatePrivateKeyFromString(key, algorithm) : generatePublicKeyFromString(key, algorithm);
	}

	public static String getRandomKey(String algorithm){
		String algorithmType = AlgorithmLinker.getTypeOf(algorithm);
		
		if(algorithmType.equals(AlgorithmType.symmetric)) {
			return RandomStringUtils.randomAlphanumeric(6);
		}
		if(algorithmType.equals(AlgorithmType.asymmetric) && algorithm.substring(0,2).equals("RS")) {
			try {
				KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
				
				PublicKeyBroker.publicKey = Base64.encodeBase64String(keyPair.getPublic().getEncoded());
				return Base64.encodeBase64String(keyPair.getPrivate().getEncoded());
			} catch (NoSuchAlgorithmException e) {
				Output.outputError(e.getMessage());
			}
		}
		if (algorithmType.equals(AlgorithmType.asymmetric) && algorithm.substring(0,2).equals("ES")) {
			try {
				KeyPair keyPair = KeyPairGenerator.getInstance("EC").generateKeyPair();
				return Base64.encodeBase64String(keyPair.getPrivate().getEncoded());
			} catch (NoSuchAlgorithmException e) {
				Output.outputError(e.getMessage());
			}
		}
		throw new RuntimeException("Cannot get random key of provided algorithm as it does not seem valid HS, RS or ES");
	}

	/**
	 * @return gets the type (asym, sym, none) of the provided @param algo
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

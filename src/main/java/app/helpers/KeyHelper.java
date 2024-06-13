package app.helpers;

import static org.apache.commons.lang.StringUtils.isNotEmpty;

import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.RandomStringUtils;

import app.algorithm.AlgorithmType;
import app.algorithm.AlgorithmWrapper;

public class KeyHelper {

	KeyHelper() {

	}

	private static final String[] KEY_BEGIN_MARKERS = new String[] { "-----BEGIN PUBLIC KEY-----", "-----BEGIN CERTIFICATE-----" };
	private static final String[] KEY_END_MARKERS = new String[] { "-----END PUBLIC KEY-----", "-----END CERTIFICATE-----" };
	public static final String HMAC_SHA_256 = "HmacSHA256";

	public static String getRandomKey(String algorithm) {
		AlgorithmType algorithmType = AlgorithmWrapper.getTypeOf(algorithm);

		if (algorithmType.equals(AlgorithmType.SYMMETRIC)) {
			return RandomStringUtils.randomAlphanumeric(6);
		}
		if (algorithmType.equals(AlgorithmType.ASYMMETRIC) && algorithm.startsWith("RS")) {
			try {
				KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();

				PublicKeyBroker.publicKey = Base64.encodeBase64String(keyPair.getPublic().getEncoded());
				return Base64.encodeBase64String(keyPair.getPrivate().getEncoded());
			} catch (NoSuchAlgorithmException e) {
				Output.outputError(e.getMessage());
			}
		}
		if (algorithmType.equals(AlgorithmType.ASYMMETRIC) && algorithm.startsWith("ES")) {
			try {
				KeyPair keyPair = KeyPairGenerator.getInstance("EC").generateKeyPair();
				return Base64.encodeBase64String(keyPair.getPrivate().getEncoded());
			} catch (NoSuchAlgorithmException e) {
				Output.outputError(e.getMessage());
			}
		}
		throw new IllegalArgumentException("Cannot get random key of provided algorithm as it does not seem valid HS, RS or ES");
	}

	public static PrivateKey generatePrivateKeyFromString(String key, String algorithm) {
		PrivateKey privateKey = null;
		if (isNotEmpty(key)) {
			key = cleanKey(key);
			try {
				byte[] keyByteArray = Base64.decodeBase64(key);
				KeyFactory kf = KeyFactory.getInstance(algorithm);
				EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyByteArray);
				privateKey = kf.generatePrivate(keySpec);
			} catch (Exception e) {
				Output.outputError("Error generating private key with input string '" + key + "' and algorithm '" + algorithm + "' - " + e.getMessage() + " - ");
			}
		}
		return privateKey;
	}

	public static String cleanKey(String key) {
		for (String keyBeginMarker : KEY_BEGIN_MARKERS) {
			key = key.replace(keyBeginMarker, "");
		}
		for (String keyEndMarker : KEY_END_MARKERS) {
			key = key.replace(keyEndMarker, "");
		}
		key = key.replaceAll("\\s+", "").replaceAll("\\r+", "").replaceAll("\\n+", "");

		return key;
	}

	public static RSAPublicKey loadCVEAttackPublicKey() {
		String publicPEM = KeyHelper.cleanKey(Config.cveAttackModePublicKey);
		KeyFactory kf;
		try {
			kf = KeyFactory.getInstance("RSA");
			X509EncodedKeySpec keySpecX509 = new X509EncodedKeySpec(java.util.Base64.getDecoder().decode(publicPEM));
			return (RSAPublicKey) kf.generatePublic(keySpecX509);
		} catch (Exception e) {
			Output.outputError("Could not load public key - " + e.getMessage());
			e.printStackTrace();
		}
		return null;
	}

	private static PublicKey generatePublicKeyFromString(String key, String algorithm) {
		PublicKey publicKey = null;
		if (isNotEmpty(key)) {
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

	public static Key getKeyInstance(String key, String algorithm, boolean isPrivate) {
		return isPrivate ? generatePrivateKeyFromString(key, algorithm) : generatePublicKeyFromString(key, algorithm);
	}

	public static byte[] calcHmacSha256(byte[] secretKey, byte[] message) {
		byte[] hmacSha256 = null;
		try {
			Mac mac = Mac.getInstance(HMAC_SHA_256);
			SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey, HMAC_SHA_256);
			mac.init(secretKeySpec);
			hmacSha256 = mac.doFinal(message);
		} catch (Exception e) {
			Output.outputError("Exception during " + HMAC_SHA_256 + ": " + e.getMessage());
		}
		return hmacSha256;
	}
}

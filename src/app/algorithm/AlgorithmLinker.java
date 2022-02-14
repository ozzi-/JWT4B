package app.algorithm;

import static org.apache.commons.lang.StringUtils.isNotEmpty;

import java.io.UnsupportedEncodingException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.AlgorithmMismatchException;
import com.auth0.jwt.interfaces.ECDSAKeyProvider;
import com.auth0.jwt.interfaces.RSAKeyProvider;

import app.helpers.KeyHelper;
import app.helpers.Output;

public class AlgorithmLinker {

  private AlgorithmLinker() {
  }

  protected static final String[] keyBeginMarkers = new String[]{"-----BEGIN PUBLIC KEY-----",
      "-----BEGIN CERTIFICATE-----"};
  protected static final String[] keyEndMarkers = new String[]{"-----END PUBLIC KEY-----", "-----END CERTIFICATE-----"};

  public static final app.algorithm.AlgorithmWrapper none = new app.algorithm.AlgorithmWrapper("none",
      AlgorithmType.NONE);
  public static final app.algorithm.AlgorithmWrapper HS256 = new app.algorithm.AlgorithmWrapper("HS256",
      AlgorithmType.SYMMETRIC);
  public static final app.algorithm.AlgorithmWrapper HS384 = new app.algorithm.AlgorithmWrapper("HS384",
      AlgorithmType.SYMMETRIC);
  public static final app.algorithm.AlgorithmWrapper HS512 = new app.algorithm.AlgorithmWrapper("HS512",
      AlgorithmType.SYMMETRIC);
  public static final app.algorithm.AlgorithmWrapper RS256 = new app.algorithm.AlgorithmWrapper("RS256",
      AlgorithmType.ASYMMETRIC);
  public static final app.algorithm.AlgorithmWrapper RS384 = new app.algorithm.AlgorithmWrapper("RS384",
      AlgorithmType.ASYMMETRIC);
  public static final app.algorithm.AlgorithmWrapper RS512 = new app.algorithm.AlgorithmWrapper("RS512",
      AlgorithmType.ASYMMETRIC);
  public static final app.algorithm.AlgorithmWrapper ES256 = new app.algorithm.AlgorithmWrapper("ES256",
      AlgorithmType.ASYMMETRIC);
  public static final app.algorithm.AlgorithmWrapper ES256K = new app.algorithm.AlgorithmWrapper("ES256K",
      AlgorithmType.ASYMMETRIC);
  public static final app.algorithm.AlgorithmWrapper ES384 = new app.algorithm.AlgorithmWrapper("ES384",
      AlgorithmType.ASYMMETRIC);
  public static final app.algorithm.AlgorithmWrapper ES512 = new app.algorithm.AlgorithmWrapper("ES512",
      AlgorithmType.ASYMMETRIC);

  private static final app.algorithm.AlgorithmWrapper[] supportedAlgorithms = {none, HS256, HS384, HS512, RS256, RS384,
      RS512, ES256, ES256K, ES384, ES512};

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

  /**
   * @param algo
   * @param key  - either the secret or the private key
   * @return the algorithm element from the library, if nothing matches the
   * none algorithm element is returned
   * @throws IllegalArgumentException
   * @throws UnsupportedEncodingException
   */
  public static Algorithm getVerifierAlgorithm(String algo, String key) throws UnsupportedEncodingException {
    return getAlgorithm(algo, key);
  }

  public static Algorithm getSignerAlgorithm(String algo, String key) throws UnsupportedEncodingException {
    return getAlgorithm(algo, key);
  }

  private static Algorithm getAlgorithm(String algo, String key) throws IllegalArgumentException {
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
    throw new AlgorithmMismatchException("Unsupported algorithm '" + algo + "'");
  }

  public static Key getKeyInstance(String key, String algorithm, boolean isPrivate) {
    return isPrivate ?
        KeyHelper.generatePrivateKeyFromString(key, algorithm) :
        generatePublicKeyFromString(key, algorithm);
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
    return AlgorithmType.NONE;
  }
}

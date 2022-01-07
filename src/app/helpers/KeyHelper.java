package app.helpers;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.RandomStringUtils;

import app.algorithm.AlgorithmLinker;
import app.algorithm.AlgorithmType;

import static org.apache.commons.lang.StringUtils.isNotEmpty;

public class KeyHelper {

  public static final String[] keyHeaderBeginMarkers = new String[]{"-----BEGIN PUBLIC KEY-----",
      "-----BEGIN CERTIFICATE-----"};
  public static final String[] keyFooterBeingMarkers = new String[]{"-----END PUBLIC KEY-----",
      "-----END CERTIFICATE-----"};

  public static String getRandomKey(String algorithm) {
    String algorithmType = AlgorithmLinker.getTypeOf(algorithm);

    if (algorithmType.equals(AlgorithmType.symmetric)) {
      return RandomStringUtils.randomAlphanumeric(6);
    }
    if (algorithmType.equals(AlgorithmType.asymmetric) && algorithm.startsWith("RS")) {
      try {
        KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();

        PublicKeyBroker.publicKey = Base64.encodeBase64String(keyPair.getPublic().getEncoded());
        return Base64.encodeBase64String(keyPair.getPrivate().getEncoded());
      } catch (NoSuchAlgorithmException e) {
        Output.outputError(e.getMessage());
      }
    }
    if (algorithmType.equals(AlgorithmType.asymmetric) && algorithm.startsWith("ES")) {
      try {
        KeyPair keyPair = KeyPairGenerator.getInstance("EC").generateKeyPair();
        return Base64.encodeBase64String(keyPair.getPrivate().getEncoded());
      } catch (NoSuchAlgorithmException e) {
        Output.outputError(e.getMessage());
      }
    }
    throw new RuntimeException("Cannot get random key of provided algorithm as it does not seem valid HS, RS or ES");
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
        Output.outputError(
            "Error generating private key with input string '" + key + "' and algorithm '" + algorithm + "' - "
                + e.getMessage() + " - ");
      }
    }
    return privateKey;
  }

  public static String cleanKey(String key) {
    for (String keyBeginMarker : keyHeaderBeginMarkers) {
      key = key.replace(keyBeginMarker, "");
    }
    for (String keyEndMarker : keyFooterBeingMarkers) {
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


}

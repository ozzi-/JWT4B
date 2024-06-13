package app.helpers;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import org.apache.commons.codec.binary.Hex;

import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.JsonNode;

import app.algorithm.AlgorithmWrapper;
import model.CustomJWToken;

public class O365 {

	O365() {

	}

	public static boolean isO365Request(CustomJWToken token, String tokenalgo) {
		return token.getHeaderJsonNode().get("ctx") != null && tokenalgo.toUpperCase().contains(AlgorithmWrapper.HS256.name());
	}

	public static void handleO365(String key, CustomJWToken token) throws NoSuchAlgorithmException {
		String label = "AzureAD-SecureConversation";
		String ctx = token.getHeaderJsonNode().get("ctx").asText();
		byte[] ctxbytes = Base64.getDecoder().decode(ctx);

		JsonNode kdfVer = token.getHeaderJsonNode().get("kdf_ver");
		boolean tokenCreatedWithKDFv2 = kdfVer != null && kdfVer.asInt() == 2;
		if (tokenCreatedWithKDFv2) {
			byte[] fullctxbytes = new byte[24 + token.getPayloadJson().replace(" ", "").replace("\n", "").length()];
			System.arraycopy(ctxbytes, 0, fullctxbytes, 0, 24);
			System.arraycopy(token.getPayloadJson().replace(" ", "").replace("\n", "").getBytes(StandardCharsets.ISO_8859_1), 0, fullctxbytes, 24,
					token.getPayloadJson().replace(" ", "").replace("\n", "").length());
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			ctxbytes = digest.digest(fullctxbytes);
		}

		byte[] newArr = new byte[4 + label.getBytes(StandardCharsets.UTF_8).length + 1 + ctxbytes.length + 4];
		System.arraycopy(new byte[] { (byte) 0x00, 0x00, 0x00, 0x01 }, 0, newArr, 0, 4);
		System.arraycopy(label.getBytes(StandardCharsets.UTF_8), 0, newArr, 4, 26);
		System.arraycopy(new byte[] { (byte) 0x00 }, 0, newArr, 30, 1);
		System.arraycopy(ctxbytes, 0, newArr, 31, ctxbytes.length);
		System.arraycopy(new byte[] { (byte) 0x00, 0x00, 0x01, 0x00 }, 0, newArr, newArr.length - 4, 4);
		byte[] keyData = key.getBytes(StandardCharsets.ISO_8859_1);
		byte[] hmacSha256 = KeyHelper.calcHmacSha256(keyData, newArr);

		Algorithm algo = AlgorithmWrapper.getSignerAlgorithm(token.getAlgorithm(), hmacSha256);
		Output.output("Signing with MS O365 derived key: " + Hex.encodeHexString(hmacSha256));
		token.calculateAndSetSignature(algo);
	}
}

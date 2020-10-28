package model;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.TimeZone;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.StringUtils;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.interfaces.Claim;
import com.eclipsesource.json.Json;
import com.eclipsesource.json.JsonObject;
import com.eclipsesource.json.JsonValue;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import app.helpers.Minify;
import app.helpers.Output;

/* 
 * This Class is implemented separately to get raw access to the content of the Tokens. 
 * The JWTDecoder class cannot be extended because it is final
 */

public class CustomJWToken extends JWT {
	private String headerJson;
	private String payloadJson;
	private byte[] signature;
	private List<TimeClaim> timeClaimList = new ArrayList<TimeClaim>();
	private String originalToken;

	public CustomJWToken(String token) {
		originalToken = token;
		if (token != null) {
			final String[] parts = splitToken(token);
			try {
				headerJson = StringUtils.newStringUtf8(Base64.decodeBase64(parts[0]));
				payloadJson = StringUtils.newStringUtf8(Base64.decodeBase64(parts[1]));
				checkRegisteredClaims(payloadJson);
			} catch (NullPointerException e) {
				Output.outputError("The UTF-8 Charset isn't initialized (" + e.getMessage() + ")");
			}
			signature = Base64.decodeBase64(parts[2]);
		}
	}

	public List<TimeClaim> getTimeClaimList() {
		return timeClaimList;
	}

	private void checkRegisteredClaims(String payloadJson) {
		TimeZone.setDefault(TimeZone.getTimeZone("UTC"));
		JsonObject object;
		try {
			object = Json.parse(payloadJson).asObject();
		} catch (Exception e) {
			Output.output("Could not parse claims - " + e.getMessage());
			return;
		}

		JsonValue exp = object.get("exp");
		long curUT = System.currentTimeMillis() / 1000L;
		if (exp != null) {
			try {
				long expUT = getDateJSONValue(exp);
				java.util.Date time = new java.util.Date((long) expUT * 1000);
				String expDate = time.toString();
				boolean expValid = expUT > curUT;
				timeClaimList.add(new TimeClaim("[exp] Expired", expDate, expUT, expValid));
			} catch (Exception e) {
				Output.output("Could not parse claim (exp) - " + e.getMessage() + " - " + e.getCause());
			}
		}

		JsonValue nbf = object.get("nbf");
		if (nbf != null) {
			try {
				long nbfUT = getDateJSONValue(nbf);
				java.util.Date time = new java.util.Date((long) nbfUT * 1000);
				String nbfDate = time.toString();
				boolean nbfValid = nbfUT <= curUT;
				timeClaimList.add(new TimeClaim("[nbf] Not before", nbfDate, nbfUT, nbfValid));
			} catch (Exception e) {
				Output.output("Could not parse claim (nbf) - " + e.getMessage() + " - " + e.getCause());
			}
		}

		JsonValue iat = object.get("iat");
		if (iat != null) {
			try {
				long iatUT = getDateJSONValue(iat);
				java.util.Date time = new java.util.Date((long) iatUT * 1000);
				String iatDate = time.toString();
				timeClaimList.add(new TimeClaim("[iat] Issued at ", iatDate, iatUT));
			} catch (Exception e) {
				Output.output("Could not parse claim (iat) - " + e.getMessage() + " - " + e.getCause());
			}
		}
	}

	private long getDateJSONValue(JsonValue jv) {
		long utL;
		try {
			utL = jv.asLong();
		} catch (Exception e) {
			Double utD = jv.asDouble();
			utL = utD.longValue();
		}
		return utL;
	}

	public CustomJWToken(String headerJson, String payloadJson, String signatureB64) {
		// TODO check if valid json
		this.headerJson = headerJson;
		this.payloadJson = payloadJson;
		this.signature = Base64.decodeBase64(signatureB64);
	}

	public String getHeaderJson() {
		return headerJson;
	}

	public String getPayloadJson() {
		return payloadJson;
	}

	public JsonNode getHeaderJsonNode() {
		ObjectMapper objectMapper = new ObjectMapper();
		try {
			return objectMapper.readTree(getHeaderJson());
		} catch (IOException e) {
			Output.outputError("IO exception reading json tree (" + e.getMessage() + ")");
			return null;
		}
	}

	public void calculateAndSetSignature(Algorithm algorithm) {
		if (jsonMinify(getHeaderJson()) != null && jsonMinify(getPayloadJson()) != null) {
			byte[] payloadBytes = b64(jsonMinify(getPayloadJson())).getBytes(StandardCharsets.UTF_8);
			byte[] headerBytes = b64(jsonMinify(getHeaderJson())).getBytes(StandardCharsets.UTF_8);
			signature = algorithm.sign(headerBytes, payloadBytes);
		}
	}

	private String jsonMinify(String json) {
		try {
			String jsonMinify = new Minify().minify(json);
			return jsonMinify;
		} catch (Exception e) {
			Output.outputError("Could not minify json: " + e.getMessage());
			return null;
		}
	}

	public String getToken() {
		if (jsonMinify(getHeaderJson()) != null && jsonMinify(getPayloadJson()) != null) {
			String content = String.format("%s.%s", b64(jsonMinify(getHeaderJson())),
					b64(jsonMinify((getPayloadJson()))));
			String signatureEncoded = Base64.encodeBase64URLSafeString(this.signature);
			return String.format("%s.%s", content, signatureEncoded);
		}
		return null;
	}

	private String b64(String input) {
		return Base64.encodeBase64URLSafeString(input.getBytes(StandardCharsets.UTF_8));
	}

	public static boolean isValidJWT(String token) {
		if (org.apache.commons.lang.StringUtils.countMatches(token, ".") != 2) {
			return false;
		}
		try {
			JWT.decode(token);
			return true;
		} catch (JWTDecodeException exception) {
		}
		return false;
	}

	// Method copied from:
	// https://github.com/auth0/java-jwt/blob/9148ca20adf679721591e1d012b7c6b8c4913d75/lib/src/main/java/com/auth0/jwt/TokenUtils.java#L14
	// Cannot be reused, it's visibility is protected.
	static String[] splitToken(String token) throws JWTDecodeException {
		String[] parts = token.split("\\.");
		if (parts.length == 2 && token.endsWith(".")) {
			// Tokens with alg='none' have empty String as Signature.
			parts = new String[] { parts[0], parts[1], "" };
		}
		if (parts.length != 3) {
			throw new JWTDecodeException(
					String.format("The token was expected to have 3 parts, but got %s.", parts.length));
		}
		return parts;
	}

	public void setHeaderJson(String headerJson) {
		this.headerJson = headerJson;
	}

	public void setPayloadJson(String payloadJson) {
		this.payloadJson = payloadJson;
	}

	public List<String> getAudience() {
		throw new UnsupportedOperationException();
	}

	public Claim getClaim(String arg0) {
		throw new UnsupportedOperationException();
	}

	public Map<String, Claim> getClaims() {
		throw new UnsupportedOperationException();
	}

	public Date getExpiresAt() {
		throw new UnsupportedOperationException();
	}

	public String getId() {
		throw new UnsupportedOperationException();
	}

	public Date getIssuedAt() {
		throw new UnsupportedOperationException();
	}

	public String getIssuer() {
		throw new UnsupportedOperationException();
	}

	public Date getNotBefore() {
		throw new UnsupportedOperationException();
	}

	public String getSubject() {
		throw new UnsupportedOperationException();
	}

	public String getAlgorithm() {
		String algorithm = "";
		try {
			algorithm = getHeaderJsonNode().get("alg").asText();
		} catch (Exception e) {
		}
		return algorithm;
	}

	public String getContentType() {
		return getHeaderJsonNode().get("typ").asText();
	}

	public Claim getHeaderClaim(String arg0) {
		throw new UnsupportedOperationException();
	}

	public String getKeyId() {
		throw new UnsupportedOperationException();
	}

	public String getType() {
		throw new UnsupportedOperationException();
	}

	public String getSignature() {
		return Base64.encodeBase64URLSafeString(this.signature);
	}

	public void setSignature(String signature) {
		this.signature = Base64.decodeBase64(signature);
	}

	public String getOriginalToken() {
		return originalToken;
	}
}

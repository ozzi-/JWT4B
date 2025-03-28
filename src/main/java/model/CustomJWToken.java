package model;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.TimeZone;
import java.util.zip.GZIPInputStream;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.StringUtils;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.eclipsesource.json.Json;
import com.eclipsesource.json.JsonObject;
import com.eclipsesource.json.JsonValue;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import app.helpers.Minify;
import app.helpers.Output;

/*
 * This Class is implemented separately to get raw access to the content of the Tokens.
 * The JWTDecoder class cannot be extended because it is final
 */

public class CustomJWToken extends JWT {

	private boolean isMinified;
	private String headerJson;
	private String payloadJson;
	private byte[] signature;
	private final List<TimeClaim> timeClaimList = new ArrayList<>();
	private boolean builtSuccessfully = true;

	public CustomJWToken(String token) {
		construct(token, false);
	}
	
	public CustomJWToken(String token, boolean log) {
		construct(token, log);
	}

	private void construct(String token, boolean log) {
		if (token != null) {
			final String[] parts = splitToken(token,log);
			try {
				headerJson = StringUtils.newStringUtf8(Base64.decodeBase64(parts[0]));
				byte[] payloadBase64 = Base64.decodeBase64(parts[1]);
				payloadJson = StringUtils.newStringUtf8(payloadBase64);
				isMinified = (isMinified(payloadJson) && isMinified(headerJson));
				JsonObject headerObject;
				try {
					headerObject = Json.parse(headerJson).asObject();
					if (headerObject.getString("zip", "").equalsIgnoreCase("GZIP")) {
						GZIPInputStream gis = new GZIPInputStream(new ByteArrayInputStream(payloadBase64));
						ByteArrayOutputStream buf = new ByteArrayOutputStream();
						for (int result = gis.read(); result != -1; result = gis.read()) {
							buf.write((byte) result);
						}
						payloadJson = buf.toString(StandardCharsets.UTF_8);
					}
				} catch (IOException e) {
					Output.outputError("Could not gunzip JSON - " + e.getMessage(),log);
					builtSuccessfully = false;
				} catch (Exception e) {
					Output.outputError("Could not parse header - " + e.getMessage(),log);
					builtSuccessfully = false;
				}
				checkRegisteredClaims(payloadJson,log);
			} catch (NullPointerException e) {
				Output.outputError("The UTF-8 Charset isn't initialized (" + e.getMessage() + ")",log);
				builtSuccessfully = false;
			}
			signature = Base64.decodeBase64(parts[2]);
		}
	}

	private boolean isMinified(String json) {
		ObjectMapper objectMapper = new ObjectMapper();
		try {
			JsonNode jsonNode = objectMapper.readValue(json, JsonNode.class);
			return jsonNode.toString().equals(json);
		} catch (JsonProcessingException e) {
			e.printStackTrace();
		}
		return false;
	}

	public List<TimeClaim> getTimeClaimList() {
		return timeClaimList;
	}

	private void checkRegisteredClaims(String payloadJson, boolean log) {
		TimeZone.setDefault(TimeZone.getTimeZone("UTC"));
		JsonObject object;
		try {
			object = Json.parse(payloadJson).asObject();
		} catch (Exception e) {
			Output.output("Could not parse claims - " + e.getMessage(),log);
			return;
		}

		JsonValue exp = object.get("exp");
		long curUT = System.currentTimeMillis() / 1000L;
		if (exp != null) {
			try {
				long expUT = getDateJSONValue(exp);
				java.util.Date time = new java.util.Date(expUT * 1000);
				String expDate = time.toString();
				boolean expValid = expUT > curUT;
				timeClaimList.add(new TimeClaim("[exp] Expired", expDate, expUT, expValid, true));
			} catch (Exception e) {
				Output.output("Could not parse claim (exp) - " + e.getMessage() + " - " + e.getCause());
			}
		}

		JsonValue nbf = object.get("nbf");
		if (nbf != null) {
			try {
				long nbfUT = getDateJSONValue(nbf);
				java.util.Date time = new java.util.Date(nbfUT * 1000);
				String nbfDate = time.toString();
				boolean nbfValid = nbfUT <= curUT;
				timeClaimList.add(new TimeClaim("[nbf] Not before", nbfDate, nbfUT, nbfValid, true));
			} catch (Exception e) {
				Output.output("Could not parse claim (nbf) - " + e.getMessage() + " - " + e.getCause());
			}
		}

		JsonValue iat = object.get("iat");
		if (iat != null) {
			try {
				long iatUT = getDateJSONValue(iat);
				java.util.Date time = new java.util.Date(iatUT * 1000);
				String iatDate = time.toString();
				timeClaimList.add(new TimeClaim("[iat] Issued at ", iatDate, iatUT, true, false));
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
			return null;
		}
	}

	public void calculateAndSetSignature(Algorithm algorithm) {
		if (jsonMinify(getHeaderJson()) != null && jsonMinify(getPayloadJson()) != null) {
			byte[] payloadBytes = b64(Objects.requireNonNull(jsonMinify(getPayloadJson()))).getBytes(StandardCharsets.UTF_8);
			byte[] headerBytes = b64(Objects.requireNonNull(jsonMinify(getHeaderJson()))).getBytes(StandardCharsets.UTF_8);
			signature = algorithm.sign(headerBytes, payloadBytes);
		}
	}

	private String jsonMinify(String json) {
		try {
			return new Minify().minify(json);
		} catch (Exception e) {
			Output.outputError("Could not minify json: " + e.getMessage());
			return null;
		}
	}

	public String getToken() {
		if (jsonMinify(getHeaderJson()) != null && jsonMinify(getPayloadJson()) != null) {
			String content = String.format("%s.%s", b64(jsonMinify(getHeaderJson())), b64(jsonMinify((getPayloadJson()))));
			String signatureEncoded = Base64.encodeBase64URLSafeString(this.signature);
			return String.format("%s.%s", content, signatureEncoded);
		}
		Output.outputError("Could not get token as some parts are to be null");
		return null;
	}

	private String b64(String input) {
		return Base64.encodeBase64URLSafeString(input.getBytes(StandardCharsets.UTF_8));
	}

	public static boolean isValidJWT(String token, boolean log) {
		if (org.apache.commons.lang.StringUtils.countMatches(token, ".") != 2) {
			return false;
		}
		try {
			CustomJWToken cjwt = new CustomJWToken(token,log);
			if (!cjwt.isBuiltSuccessful()) {
				return false;
			}
			String tok = cjwt.getToken();
			if (tok == null) {
				return false;
			}
			JWT.decode(tok);
			return true;
		} catch (Exception ignored) {
			// ignored
		}
		return false;
	}

	// Method copied from:
	// https://github.com/auth0/java-jwt/blob/9148ca20adf679721591e1d012b7c6b8c4913d75/lib/src/main/java/com/auth0/jwt/TokenUtils.java#L14
	// Cannot be reused, it's visibility is protected.
	static String[] splitToken(String token, boolean log) throws JWTDecodeException {
		String[] parts = token.split("\\.");
		if (parts.length == 2 && token.endsWith(".")) {
			// Tokens with alg='none' have empty String as Signature.
			parts = new String[] { parts[0], parts[1], "" };
		}
		if (parts.length != 3) {
			if(log) {
				throw new JWTDecodeException(String.format("The token was expected to have 3 parts, but got %s.", parts.length));				
			}
			return new String[] {};
		}
		return parts;
	}

	public CustomJWToken setHeaderJson(String headerJson) {
		this.headerJson = headerJson;
		return this;
	}

	public boolean isMinified() {
		return isMinified;
	}

	public String getAlgorithm() {
		String algorithm = "";
		try {
			algorithm = getHeaderJsonNode().get("alg").asText();
		} catch (Exception ignored) {
			// ignored
		}
		return algorithm;
	}

	public String getSignature() {
		return Base64.encodeBase64URLSafeString(this.signature);
	}

	public CustomJWToken setSignature(String signature) {
		this.signature = Base64.decodeBase64(signature);
		return this;
	}

	public boolean isBuiltSuccessful() {
		return builtSuccessfully;
	}

}

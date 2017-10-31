package app.helpers;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.TimeZone;

import model.TimeClaim;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.StringUtils;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.interfaces.Claim;
import com.eclipsesource.json.Json;
import com.eclipsesource.json.JsonObject;
import com.eclipsesource.json.JsonValue;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

/* 
 * This Class is implemented separately to get raw access to the content of the Tokens. 
 * The JWTDecoder class cannot be extended because it is final
 */

public class CustomJWToken extends JWT {
	private String headerJson;
	private String payloadJson;
	private byte[] signature;
	private List<TimeClaim> timeClaimList = new ArrayList<TimeClaim>();
	
	public CustomJWToken(String token) {
		final String[] parts = splitToken(token);
		try {
			headerJson = StringUtils.newStringUtf8(Base64.decodeBase64(parts[0]));
			payloadJson = StringUtils.newStringUtf8(Base64.decodeBase64(parts[1]));
			checkRegisteredClaims(payloadJson);
		} catch (NullPointerException e) {
			ConsoleOut.output("The UTF-8 Charset isn't initialized ("+e.getMessage()+")");
		}
		signature = Base64.decodeBase64(parts[2]);
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
			ConsoleOut.output("Can't parse claims - "+e.getMessage());
			return;
		}
		JsonValue exp = object.get("exp");
		long curUT = System.currentTimeMillis() / 1000L;
		if(exp!=null){
			try{
				long expUT = exp.asLong();
				java.util.Date time=new java.util.Date((long)expUT*1000);
				String expDate = time.toString();
				boolean expValid = expUT>curUT;
				timeClaimList.add(new TimeClaim("[exp] Expired", expDate, expUT, expValid));
			}catch (Exception e) {
				ConsoleOut.output("Could not parse claim - "+e.getMessage());
			}
		}
		JsonValue nbf = object.get("nbf");
		if(nbf!=null){
			try{
				long nbfUT = nbf.asLong();
				java.util.Date time=new java.util.Date((long)nbfUT*1000);
				String nbfDate = time.toString();
				boolean nbfValid = nbfUT<=curUT;
				timeClaimList.add(new TimeClaim("[nbf] Not before", nbfDate, nbfUT, nbfValid));
			}catch (Exception e) {
				ConsoleOut.output("Could not parse claim - "+e.getMessage());
			}
		}
		JsonValue iat = object.get("iat");
		if(iat!=null){
			try{
				long iatUT = iat.asLong();
				java.util.Date time=new java.util.Date((long)iatUT*1000);
				String iatDate = time.toString();
				timeClaimList.add(new TimeClaim("[iat] Issued at ", iatDate, iatUT));				
			}catch (Exception e) {
				ConsoleOut.output("Could not parse claim - "+e.getMessage());
			}
		}
	}


	public CustomJWToken(String headerJson, String payloadJson, String signature) {
		this.headerJson = headerJson;
		this.payloadJson = payloadJson;
		this.signature = Base64.decodeBase64(signature);
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
			ConsoleOut.output("IO exception reading json tree ("+e.getMessage()+")");
			return null;
		}
	}
	
	public void calculateAndSetSignature(Algorithm algorithm){ 
		 byte[] contentBytes = String.format("%s.%s", b64(jsonMinify(getHeaderJson())), b64(jsonMinify(getPayloadJson()))).getBytes(StandardCharsets.UTF_8);
		 signature = algorithm.sign(contentBytes);
	}

	public JsonNode getPayloadJsonNode() {
		ObjectMapper objectMapper = new ObjectMapper();
		try {
			return objectMapper.readTree(getPayloadJson());
		} catch (IOException e) {
			return null;
		}
	}

	public void setHeaderJsonNode(JsonNode headerPayloadJson) {
		ObjectMapper objectMapper = new ObjectMapper();
		try {
			this.headerJson = objectMapper.writeValueAsString(headerPayloadJson);
		} catch (JsonProcessingException e) {
			ConsoleOut.output("Setting header for json failed ("+e.getMessage()+")");
		}
	}

	public void setPayloadJsonNode(JsonNode payloadJsonNode) {
		ObjectMapper objectMapper = new ObjectMapper();
		try {
			this.payloadJson = objectMapper.writeValueAsString(payloadJsonNode);
		} catch (JsonProcessingException e) {
			ConsoleOut.output("Setting payload for json failed ("+e.getMessage()+")");
		}
	}

	private String jsonMinify(String json){
	    ObjectMapper objectMapper = new ObjectMapper();
	    JsonNode jsonNode = null;
		try {
			jsonNode = objectMapper.readValue(json, JsonNode.class);
			return (jsonNode.toString());
		} catch (IOException e) {
			ConsoleOut.output("Could not minify json: "+e.getMessage());
		}
		return json;
	}
	
	@Override
	public String getToken() {
		String content = String.format("%s.%s", b64(jsonMinify(getHeaderJson())), b64(jsonMinify((getPayloadJson()))));

		String signatureEncoded = Base64.encodeBase64URLSafeString(this.signature);

		return String.format("%s.%s", content, signatureEncoded);
	}

	private String b64(String input) { 
		return Base64.encodeBase64URLSafeString(input.getBytes(StandardCharsets.UTF_8));
	}
	
	public static boolean isValidJWT(String token){
		if(org.apache.commons.lang.StringUtils.countMatches(token, ".")!=2){
			return false;
		}
		try {
		    JWT.decode(token);
		    return true;
		} catch (JWTDecodeException exception){ }
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
	
	@Override
	public List<String> getAudience() {
		throw new UnsupportedOperationException();
	}

	@Override
	public Claim getClaim(String arg0) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Map<String, Claim> getClaims() {
		throw new UnsupportedOperationException();
	}

	@Override
	public Date getExpiresAt() {
		throw new UnsupportedOperationException();
	}

	@Override
	public String getId() {
		throw new UnsupportedOperationException();
	}

	@Override
	public Date getIssuedAt() {
		throw new UnsupportedOperationException();
	}

	@Override
	public String getIssuer() {
		throw new UnsupportedOperationException();
	}

	@Override
	public Date getNotBefore() {
		throw new UnsupportedOperationException();
	}

	@Override
	public String getSubject() {
		throw new UnsupportedOperationException();
	}

	@Override
	public String getAlgorithm() {
		String algorithm ="";
		try {
			algorithm = getHeaderJsonNode().get("alg").asText();			
		} catch (Exception e) {
		}
		return algorithm;
	}

	@Override
	public String getContentType() {
		return getHeaderJsonNode().get("typ").asText();
	}

	@Override
	public Claim getHeaderClaim(String arg0) {
		throw new UnsupportedOperationException();
	}

	@Override
	public String getKeyId() {
		throw new UnsupportedOperationException();
	}

	@Override
	public String getType() {
		throw new UnsupportedOperationException();
	}

	@Override
	public String getSignature() {
		return Base64.encodeBase64URLSafeString(this.signature);
	}
	
	public void setSignature(String signature) { 
		this.signature = Base64.decodeBase64(signature);
	}
}

package app;

import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.List;
import java.util.Map;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.StringUtils;

import com.auth0.jwt.JWT;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.impl.JWTParser;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.Header;
import com.auth0.jwt.interfaces.Payload;

/* 
 * This Class is implemented separately to get raw access to the content of the Tokens. 
 * The JWTDecoder class cannot be extended because it is final
 * 
 */

public class CustomJWTDecoder extends JWT {
	
	
	private String headerJson;
	private String payloadJson;
	private Header header;
	private Payload payload;
	private byte[] signature;
	private String token;

	public CustomJWTDecoder(String token) { 
		this.token = token;
        final String[] parts = splitToken(token);
        final JWTParser converter = new JWTParser();

        try {
            headerJson = StringUtils.newStringUtf8(Base64.decodeBase64(parts[0]));
            payloadJson = StringUtils.newStringUtf8(Base64.decodeBase64(parts[1]));
        } catch (NullPointerException e) {
            throw new JWTDecodeException("The UTF-8 Charset isn't initialized.", e);
        }
        header = converter.parseHeader(headerJson);
        payload = converter.parsePayload(payloadJson);
        signature = Base64.decodeBase64(parts[2]);
		
	}
	
	public String getHeaderJson() { 
		return headerJson;
	}
	
	public String getPayloadJson() { 
		return payloadJson;
	}
	

	@Override
	public String getToken() {
        String header = Base64.encodeBase64URLSafeString((headerJson.getBytes(StandardCharsets.UTF_8)));
        String payload = Base64.encodeBase64URLSafeString((payloadJson.getBytes(StandardCharsets.UTF_8)));
        String content = String.format("%s.%s", header, payload);

        String signatureEncoded = Base64.encodeBase64URLSafeString(this.signature);

        return String.format("%s.%s", content, signatureEncoded);
	}

	@Override
	public List<String> getAudience() {
		int fail = 2/0;
		return null;
		
	}

	@Override
	public Claim getClaim(String arg0) {
		int fail = 2/0;
		return null;
	}

	@Override
	public Map<String, Claim> getClaims() {
		int fail = 2/0;
		return null;
	}

	@Override
	public Date getExpiresAt() {
		int fail = 2/0;
		return null;
	}

	@Override
	public String getId() {
		int fail = 2/0;
		return null;
	}

	@Override
	public Date getIssuedAt() {
		int fail = 2/0;
		return null;
	}

	@Override
	public String getIssuer() {
		int fail = 2/0;
		return null;
	}

	@Override
	public Date getNotBefore() {
		int fail = 2/0;
		return null;
	}

	@Override
	public String getSubject() {
		int fail = 2/0;
		return null;
	}

	@Override
	public String getAlgorithm() {
		int fail = 2/0;
		return null;
	}

	@Override
	public String getContentType() {
		int fail = 2/0;
		return null;
	}

	@Override
	public Claim getHeaderClaim(String arg0) {
		int fail = 2/0;
		return null;
	}

	@Override
	public String getKeyId() {
		int fail = 2/0;
		return null;
	}

	@Override
	public String getType() {
		int fail = 2/0;
		return null;
	}

	@Override
	public String getSignature() {
		int fail = 2/0;
		return null;
	}
	
	// method copied from https://github.com/auth0/java-jwt/blob/9148ca20adf679721591e1d012b7c6b8c4913d75/lib/src/main/java/com/auth0/jwt/TokenUtils.java#L14
	// Cannot be reused, it's visibility is protected.
    static String[] splitToken(String token) throws JWTDecodeException {
        String[] parts = token.split("\\.");
        if (parts.length == 2 && token.endsWith(".")) {
            //Tokens with alg='none' have empty String as Signature.
            parts = new String[]{parts[0], parts[1], ""};
        }
        if (parts.length != 3) {
            throw new JWTDecodeException(String.format("The token was expected to have 3 parts, but got %s.", parts.length));
        }
        return parts;
    }
}

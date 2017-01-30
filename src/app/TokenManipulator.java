package app;

import java.io.UnsupportedEncodingException;

import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

public class TokenManipulator {
	
	public static String setAlgorithmToNone(String token) { 
		CustomJWTToken origToken = new CustomJWTToken(token);
		
		JsonNode header = origToken.getHeaderJsonNode();
		
		((ObjectNode)header).put("alg", "none");
		
		origToken.setHeaderJsonNode(header);
		origToken.setSignature("");
		
		return origToken.getToken();
	}

	public static String changeAlgorithm(String token, String algorithm, Boolean recalculateSignature, String signatureKey) {
		CustomJWTToken origToken = new CustomJWTToken(token);
		
		JsonNode header = origToken.getHeaderJsonNode();
		((ObjectNode)header).put("alg", algorithm);
		
		if(recalculateSignature) { 
			origToken.setHeaderJsonNode(header);
			try {
				origToken.setSignature(AlgorithmWrapper.getAlgorithm(algorithm, signatureKey));
			} catch (IllegalArgumentException | UnsupportedEncodingException e) {
				origToken.setSignature(e.getMessage());
			}
		}
		return origToken.getToken();
	}
}

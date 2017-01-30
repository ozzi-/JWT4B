package app;

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
}

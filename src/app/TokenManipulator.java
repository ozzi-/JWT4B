package app;

import java.io.UnsupportedEncodingException;

import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import app.algorithm.AlgorithmLinker;
import app.controllers.CustomJWTToken;

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

		Algorithm algorithmObject;
		try {
			algorithmObject = AlgorithmLinker.getAlgorithm(algorithm, signatureKey);
		} catch (UnsupportedEncodingException e) {
			return null;
		}

		((ObjectNode)header).put("alg", algorithmObject.getName());
		
		if(recalculateSignature) { 
			origToken.setHeaderJsonNode(header);
			origToken.setSignature(algorithmObject);
		}
		return origToken.getToken();
	}
}

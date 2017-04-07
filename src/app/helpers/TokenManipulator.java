package app.helpers;

import java.io.UnsupportedEncodingException;

import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import app.algorithm.AlgorithmLinker;

public class TokenManipulator {
	
	/**
	 * Set the algorithm to 'none'
	 * @param token
	 * @return the edited token string
	 */
	public static String setAlgorithmToNone(String token) { 
		CustomJWToken origToken = new CustomJWToken(token);
		
		JsonNode header = origToken.getHeaderJsonNode();
		
		((ObjectNode)header).put("alg", "none");
		
		origToken.setHeaderJsonNode(header);
		origToken.setSignature("");
		
		return origToken.getToken();
	}

	/**
	 * Change the algorithm of the provided token string
	 * @param token
	 * @param algorithm
	 * @param recalculateSignature 
	 * @param signatureKey
	 * @return the edited token string
	 */
	public static String changeAlgorithm(String token, String algorithm, Boolean recalculateSignature, String signatureKey) {
		CustomJWToken origToken = new CustomJWToken(token);
		
		JsonNode header = origToken.getHeaderJsonNode();

		Algorithm algorithmObject;
		try {
			algorithmObject = AlgorithmLinker.getAlgorithm(algorithm, signatureKey);
		} catch (UnsupportedEncodingException e) {
			ConsoleOut.output("Changing the tokens algorithm failed ("+e.getMessage()+")");
			return null;
		}

		((ObjectNode)header).put("alg", algorithmObject.getName());
		
		if (recalculateSignature) {
			origToken.setHeaderJsonNode(header);
			origToken.setSignature(algorithmObject);
		}
		return origToken.getToken();
	}
}

package app;

import java.io.UnsupportedEncodingException;

import com.auth0.jwt.algorithms.Algorithm;

public class AlgorithmWrapper {
	
	public static final String alg_None = "None";
	public static final String alg_HS256 = "HS256";
	public static final String alg_RS256 = "RS256";
	
	private static final String[] supportedAlgorithms = {alg_None, alg_HS256, alg_RS256};
	
	public static String[] getSupportedAlgorithms() { 
		return supportedAlgorithms;
	}
	
	public static Algorithm getAlgorithm(String algo, String key) throws IllegalArgumentException, UnsupportedEncodingException { 
		if(algo.equals(alg_HS256)) { 
			return Algorithm.HMAC256(key);
		}
		return Algorithm.none();
	}

}

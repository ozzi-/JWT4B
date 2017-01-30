package app;

import java.io.UnsupportedEncodingException;

import com.auth0.jwt.algorithms.Algorithm;

public class AlgorithmWrapper {
	private static final String[] supportedAlgorithms = {"None", "HS256", "RS256"};
	
	public static String[] getSupportedAlgorithms() { 
		return supportedAlgorithms;
	}
	
	public static Algorithm getAlgorithm(String algo, String key) throws IllegalArgumentException, UnsupportedEncodingException { 
		if(algo.equals("HS256")) { 
			return Algorithm.HMAC256(key);
		}

		return Algorithm.none();
	}

}

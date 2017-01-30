package app;

import static org.junit.Assert.*;

import org.junit.Test;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;

import app.TokenManipulator;

public class TestTokenManipulator {
	
	public static final String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ";

	@Test
	public void testAlgorithmChangedToNone() {
		JWT origToken = JWT.decode(token);
		assertNotEquals(Algorithm.none().getName(), origToken.getAlgorithm());
		
		String manipulatedTokenString = TokenManipulator.setAlgorithmToNone(token);
		JWT manipulatedToken = JWT.decode(manipulatedTokenString);
		assertEquals(Algorithm.none().getName(), manipulatedToken.getAlgorithm());
	}
	
	@Test
	public void testClaimCountIsUnchangedAfterChangingAlgorithm() { 
		JWT origToken = JWT.decode(token);
		
		String manipulatedTokenString = TokenManipulator.setAlgorithmToNone(token);
		JWT manipulatedToken = JWT.decode(manipulatedTokenString);
		assertEquals(origToken.getClaims().keySet().size(), manipulatedToken.getClaims().keySet().size());	
	}
	
	@Test
	public void testClaimsAreUnchangedAfterChangingAlgorithm() { 
		JWT origToken = JWT.decode(token);
		
		String manipulatedTokenString = TokenManipulator.setAlgorithmToNone(token);
		JWT manipulatedToken = JWT.decode(manipulatedTokenString);
		
		for(String key : origToken.getClaims().keySet()) { 
			assertEquals(origToken.getClaim(key).asString(), manipulatedToken.getClaim(key).asString());
		}
	}

}

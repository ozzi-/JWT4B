package app;

import static org.junit.Assert.*;

import org.junit.Test;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;

import app.TokenManipulator;
import app.controllers.CustomJWTToken;

public class TestAlgorightmSetToNoneManipulation {
	
	public static final String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ";

	@Test
	public void testAlgorithmChangedToNone() {
		CustomJWTToken origToken = new CustomJWTToken(token);
		assertNotEquals(Algorithm.none().getName(), origToken.getAlgorithm());
		
		String manipulatedTokenString = TokenManipulator.setAlgorithmToNone(token);
		JWT manipulatedToken = JWT.decode(manipulatedTokenString);
		assertEquals(Algorithm.none().getName(), manipulatedToken.getAlgorithm());
	}
	
	@Test
	public void testClaimCountIsUnchangedAfterChangingAlgorithm() { 
		CustomJWTToken origToken = new CustomJWTToken(token);
		
		String manipulatedTokenString = TokenManipulator.setAlgorithmToNone(token);
		CustomJWTToken manipulatedToken = new CustomJWTToken(manipulatedTokenString);
		assertEquals(origToken.getPayloadJsonNode().size(), manipulatedToken.getPayloadJsonNode().size());	
	}
	
	@Test
	public void testClaimsAreUnchangedAfterChangingAlgorithm() { 
		CustomJWTToken origToken = new CustomJWTToken(token);
		
		String manipulatedTokenString = TokenManipulator.setAlgorithmToNone(token);
		CustomJWTToken manipulatedToken = new CustomJWTToken(manipulatedTokenString);

		assertEquals(origToken.getPayloadJsonNode(), manipulatedToken.getPayloadJsonNode());
	}
	
	@Test
	public void testContentTypeIsUnchangedAfterChangingAlgorithm() { 
		CustomJWTToken origToken = new CustomJWTToken(token);
		
		String manipulatedTokenString = TokenManipulator.setAlgorithmToNone(token);
		CustomJWTToken manipulatedToken = new CustomJWTToken(manipulatedTokenString);
		
		assertEquals(origToken.getContentType(), manipulatedToken.getContentType());	
		assertNotEquals(null, manipulatedToken.getContentType());
	}
	
	@Test
	public void testIfSignatureIsEmpty() { 
		String manipulatedTokenString = TokenManipulator.setAlgorithmToNone(token);
		CustomJWTToken manipulatedToken = new CustomJWTToken(manipulatedTokenString);
		
		assertEquals(0, manipulatedToken.getSignature().length());
	}

}

package app;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;

import org.junit.Test;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;

import app.helpers.CustomJWToken;
import app.helpers.TokenManipulator;

public class TestAlgorightmSetToNoneManipulation {
	

	@Test
	public void testAlgorithmChangedToNone() {
		CustomJWToken origToken = new CustomJWToken(TestTokens.hs256_token);
		assertNotEquals(Algorithm.none().getName(), origToken.getAlgorithm());
		
		String manipulatedTokenString = TokenManipulator.setAlgorithmToNone(TestTokens.hs256_token);
		JWT manipulatedToken = JWT.decode(manipulatedTokenString);
		assertEquals(Algorithm.none().getName(), manipulatedToken.getAlgorithm());
	}
	
	@Test
	public void testClaimCountIsUnchangedAfterChangingAlgorithm() { 
		CustomJWToken origToken = new CustomJWToken(TestTokens.hs256_token);
		
		String manipulatedTokenString = TokenManipulator.setAlgorithmToNone(TestTokens.hs256_token);
		CustomJWToken manipulatedToken = new CustomJWToken(manipulatedTokenString);
		assertEquals(origToken.getPayloadJsonNode().size(), manipulatedToken.getPayloadJsonNode().size());	
	}
	
	@Test
	public void testClaimsAreUnchangedAfterChangingAlgorithm() { 
		CustomJWToken origToken = new CustomJWToken(TestTokens.hs256_token);
		
		String manipulatedTokenString = TokenManipulator.setAlgorithmToNone(TestTokens.hs256_token);
		CustomJWToken manipulatedToken = new CustomJWToken(manipulatedTokenString);

		assertEquals(origToken.getPayloadJsonNode(), manipulatedToken.getPayloadJsonNode());
	}
	
	@Test
	public void testContentTypeIsUnchangedAfterChangingAlgorithm() { 
		CustomJWToken origToken = new CustomJWToken(TestTokens.hs256_token);
		
		String manipulatedTokenString = TokenManipulator.setAlgorithmToNone(TestTokens.hs256_token);
		CustomJWToken manipulatedToken = new CustomJWToken(manipulatedTokenString);
		
		assertEquals(origToken.getContentType(), manipulatedToken.getContentType());	
		assertNotEquals(null, manipulatedToken.getContentType());
	}
	
	@Test
	public void testIfSignatureIsEmpty() { 
		String manipulatedTokenString = TokenManipulator.setAlgorithmToNone(TestTokens.hs256_token);
		CustomJWToken manipulatedToken = new CustomJWToken(manipulatedTokenString);
		
		assertEquals(0, manipulatedToken.getSignature().length());
	}

}

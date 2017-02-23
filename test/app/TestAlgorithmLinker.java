package app;

import java.io.UnsupportedEncodingException;

import org.junit.Test;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.interfaces.DecodedJWT;

import app.algorithm.AlgorithmLinker;
import app.controllers.CustomJWTToken;

public class TestAlgorithmLinker {

	@Test
	public void testWithProperKey() throws IllegalArgumentException, UnsupportedEncodingException {
		CustomJWTToken tokenObj = new CustomJWTToken(TestTokens.hs256_token);
		JWTVerifier verifier = JWT.require(AlgorithmLinker.getAlgorithm(tokenObj.getAlgorithm(), "secret")).build();
		DecodedJWT test = verifier.verify(TestTokens.hs256_token);
		test.getAlgorithm();
	}

	@Test(expected=com.auth0.jwt.exceptions.SignatureVerificationException.class)
	public void testWithFalseKey() throws IllegalArgumentException, UnsupportedEncodingException {
		CustomJWTToken tokenObj = new CustomJWTToken(TestTokens.hs256_token);
		JWTVerifier verifier = JWT.require(AlgorithmLinker.getAlgorithm(tokenObj.getAlgorithm(), "invalid")).build();
		DecodedJWT test = verifier.verify(TestTokens.hs256_token);
		test.getAlgorithm();
	}

}

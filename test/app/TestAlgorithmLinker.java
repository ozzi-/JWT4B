package app;

import java.io.UnsupportedEncodingException;

import org.junit.Test;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.interfaces.DecodedJWT;

import app.algorithm.AlgorithmLinker;
import app.helpers.CustomJWToken;

public class TestAlgorithmLinker {

	@Test
	public void testWithProperKey() throws IllegalArgumentException, UnsupportedEncodingException {
		CustomJWToken tokenObj = new CustomJWToken(TestTokens.hs256_token);
		JWTVerifier verifier = JWT.require(AlgorithmLinker.getVerifierAlgorithm(tokenObj.getAlgorithm(), "secret")).build();
		DecodedJWT test = verifier.verify(TestTokens.hs256_token);
		test.getAlgorithm();
	}

	@Test(expected=com.auth0.jwt.exceptions.SignatureVerificationException.class)
	public void testWithFalseKey() throws IllegalArgumentException, UnsupportedEncodingException {
		CustomJWToken tokenObj = new CustomJWToken(TestTokens.hs256_token);
		JWTVerifier verifier = JWT.require(AlgorithmLinker.getVerifierAlgorithm(tokenObj.getAlgorithm(), "invalid")).build();
		DecodedJWT test = verifier.verify(TestTokens.hs256_token);
		test.getAlgorithm();
	}

}

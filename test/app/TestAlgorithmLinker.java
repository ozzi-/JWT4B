package app;

import java.io.UnsupportedEncodingException;
import java.security.Key;

import org.junit.Test;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.interfaces.DecodedJWT;

import app.algorithm.AlgorithmLinker;
import model.CustomJWToken;

import static org.junit.Assert.assertNull;

public class TestAlgorithmLinker {

	@Test
	public void testHSWithProperKey() throws IllegalArgumentException, UnsupportedEncodingException {
		CustomJWToken tokenObj = new CustomJWToken(TestTokens.hs256_token);
		JWTVerifier verifier = JWT.require(AlgorithmLinker.getVerifierAlgorithm(tokenObj.getAlgorithm(), "secret")).build();
		DecodedJWT test = verifier.verify(TestTokens.hs256_token);
		test.getAlgorithm();
	}

	@Test(expected=com.auth0.jwt.exceptions.SignatureVerificationException.class)
	public void testHSWithFalseKey() throws IllegalArgumentException, UnsupportedEncodingException {
		CustomJWToken tokenObj = new CustomJWToken(TestTokens.hs256_token);
		JWTVerifier verifier = JWT.require(AlgorithmLinker.getVerifierAlgorithm(tokenObj.getAlgorithm(), "invalid")).build();
		DecodedJWT test = verifier.verify(TestTokens.hs256_token);
		test.getAlgorithm();
	}
	
	@Test
	public void testESWithProperKey() throws IllegalArgumentException, UnsupportedEncodingException {
		CustomJWToken tokenObj = new CustomJWToken(TestTokens.es256_token);
		JWTVerifier verifier = JWT.require(AlgorithmLinker.getVerifierAlgorithm(tokenObj.getAlgorithm(), TestTokens.es256_token_pub)).build();
		DecodedJWT test = verifier.verify(TestTokens.es256_token);
		test.getAlgorithm();
	}
	
	@Test(expected=com.auth0.jwt.exceptions.SignatureVerificationException.class)
	public void testESWithFalseKey() throws IllegalArgumentException, UnsupportedEncodingException {
		CustomJWToken tokenObj = new CustomJWToken(TestTokens.es256_token);
		JWTVerifier verifier = JWT.require(AlgorithmLinker.getVerifierAlgorithm(tokenObj.getAlgorithm(), TestTokens.es256_token_pub.replace("Z", "Y"))).build();
		DecodedJWT test = verifier.verify(TestTokens.es256_token);
		test.getAlgorithm();
	}

	@Test
	public void testGetKeyInstanceWithNullKeyForPublicRSA() {
		Key key = AlgorithmLinker.getKeyInstance(null, "RSA", false);

		assertNull(key);
	}

	@Test
	public void testGetKeyInstanceWithNullKeyForPublicEC() {
		Key key = AlgorithmLinker.getKeyInstance(null, "EC", false);

		assertNull(key);
	}

	@Test
	public void testGetKeyInstanceWithNullKeyForPrivateRSA() {
		Key key = AlgorithmLinker.getKeyInstance(null, "RSA", true);

		assertNull(key);
	}

	@Test
	public void testGetKeyInstanceWithNullKeyForPrivateEC() {
		Key key = AlgorithmLinker.getKeyInstance(null, "EC", true);

		assertNull(key);
	}
}

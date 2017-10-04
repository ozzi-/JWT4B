package app;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

import app.helpers.KeyValuePair;
import app.tokenposition.PostBody;

public class TestPostDetection {
	@Test
	public void testPostBody() {
		String body = "test=best&token="+TestTokens.hs256_token;
		PostBody pb = new PostBody(null,body);
		KeyValuePair result = pb.getJWTFromPostBody();
		assertEquals(TestTokens.hs256_token,result.getValue());	
	}
	
	@Test
	public void testPostBodyAlone() {
		String body = "token="+TestTokens.hs256_token;
		PostBody pb = new PostBody(null,body);
		KeyValuePair result = pb.getJWTFromPostBody();
		assertEquals(TestTokens.hs256_token,result.getValue());	
	}
	
	@Test
	public void testPostBodyReversed() {
		String body = "token="+TestTokens.hs256_token+"&test=best";
		PostBody pb = new PostBody(null,body);
		KeyValuePair result = pb.getJWTFromPostBody();
		assertEquals(TestTokens.hs256_token,result.getValue());	
	}
	@Test
	public void testPostBodyInvalid() {
		String body = "token="+TestTokens.invalid_token+"&test=best";
		PostBody pb = new PostBody(null,body);
		KeyValuePair result = pb.getJWTFromPostBody();
		assertEquals(null,result);	
	}
	@Test
	public void testPostBodyNone() {
		String body = "";
		PostBody pb = new PostBody(null,body);
		KeyValuePair result = pb.getJWTFromPostBody();
		assertEquals(null,result);	
	}
	
	@Test
	public void testPostBodyReplace() {
		String body = "test=best&token="+TestTokens.hs256_token;
		PostBody pb = new PostBody(null,body);
		@SuppressWarnings("unused")
		KeyValuePair result = pb.getJWTFromPostBody();
		pb.getToken();
		String replaced = pb.replaceTokenImpl(TestTokens.hs256_token_2,body);
		PostBody pbR = new PostBody(null,replaced);
		KeyValuePair resultR = pbR.getJWTFromPostBody();
		assertEquals(resultR.getValue(),TestTokens.hs256_token_2);	
	}
	
}

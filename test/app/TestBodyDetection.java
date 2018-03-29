package app;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;

import org.junit.Test;

import app.helpers.KeyValuePair;
import app.tokenposition.Body;

public class TestBodyDetection {
	
	@Test
	public void testBodyWithParam() {
		String body = "test=best&abc="+TestTokens.hs256_token;
		Body pb = new Body(null,body);
		KeyValuePair result = pb.getJWTFromBody();
		assertEquals(TestTokens.hs256_token,result.getValue());	
	}
	
	@Test
	public void testBodyWithoutParam() {
		String body = "a "+TestTokens.hs256_token+ " b";
		Body pb = new Body(null,body);
		KeyValuePair result = pb.getJWTFromBody();
		assertEquals(TestTokens.hs256_token,result.getValue());	
	}
	
	
	@Test
	public void testBodyWithSimpleJSON() {
		String body = "{\"aaaa\":\""+TestTokens.hs256_token+ "\"}";
		Body pb = new Body(null,body);
		KeyValuePair result = pb.getJWTFromBody();
		assertEquals(TestTokens.hs256_token,result.getValue());	
	}

	@Test
	public void testBodyWithComplexJSON() {
		String body = "{ \"bbbb\" : { \" cccc \": { \" dddd\":\""+TestTokens.hs256_token+ " \"}}}";
		Body pb = new Body(null,body);
		KeyValuePair result = pb.getJWTFromBody();
		assertNotEquals(result,null);
		assertEquals(TestTokens.hs256_token,result.getValue());	
	}
	
	@Test
	public void testBodyWithFaultyJSON() {
		String body = "{ \"bbbb\" : { \" cccc \": { \" dddd\":"+TestTokens.hs256_token+ " \"}}}";
		Body pb = new Body(null,body);
		KeyValuePair result = pb.getJWTFromBody();
		assertEquals(result,null);	
	}
	@Test
	public void testBodyWithEmptyJSON() {
		String body = "{}";
		Body pb = new Body(null,body);
		KeyValuePair result = pb.getJWTFromBody();
		assertEquals(result,null);	
	}

	@Test
	public void testBodyWithParamAlone() {
		String body = "token="+TestTokens.hs256_token;
		Body pb = new Body(null,body);
		KeyValuePair result = pb.getJWTFromBody();
		assertEquals(TestTokens.hs256_token,result.getValue());	
	}
	
	@Test
	public void testBodyWithoutParamAlone() {
		String body = TestTokens.hs256_token;
		Body pb = new Body(null,body);
		KeyValuePair result = pb.getJWTFromBody();
		assertEquals(TestTokens.hs256_token,result.getValue());	
	}
	@Test
	public void testBodyReversed() {
		String body = "egg="+TestTokens.hs256_token+"&test=best";
		Body pb = new Body(null,body);
		KeyValuePair result = pb.getJWTFromBody();
		assertEquals(TestTokens.hs256_token,result.getValue());	
	}
	@Test
	public void testBodyInvalidWithParam() {
		String body = "yo="+TestTokens.invalid_token+"&test=best";
		Body pb = new Body(null,body);
		KeyValuePair result = pb.getJWTFromBody();
		assertEquals(null,result);	
	}

	@Test
	public void testBodyInvalidWithoutParam() {
		String body = "ab "+TestTokens.invalid_token+" de";
		Body pb = new Body(null,body);
		KeyValuePair result = pb.getJWTFromBody();
		assertEquals(null,result);	
	}
	@Test
	public void testPostBodyInvalid2() {
		String body = TestTokens.hs256_token+"&";
		Body pb = new Body(null,body);
		KeyValuePair result = pb.getJWTFromBody();
		assertEquals(null,result);	
	}


	@Test
	public void testPostBodyWithoutParamsValid() {
		String body = TestTokens.hs256_token;
		Body pb = new Body(null,body);
		KeyValuePair result = pb.getJWTFromBody();
		assertEquals(result.getValue(),TestTokens.hs256_token);	
	}

	@Test
	public void testPostBodyNone() {
		String body = "";
		Body pb = new Body(null,body);
		KeyValuePair result = pb.getJWTFromBody();
		assertEquals(null,result);	
	}
	
	@Test
	public void testPostBodyReplaceWithParam() {
		String body = "test=best&token="+TestTokens.hs256_token;
		Body pb = new Body(null,body);
		@SuppressWarnings("unused")
		KeyValuePair result = pb.getJWTFromBody();
		pb.getToken();
		String replaced = pb.replaceTokenImpl(TestTokens.hs256_token_2,body);
		Body pbR = new Body(null,replaced);
		KeyValuePair resultR = pbR.getJWTFromBody();
		assertEquals(resultR.getValue(),TestTokens.hs256_token_2);	
	}
	

	@Test
	public void testPostBodyReplaceWithoutParam() {
		String body = "ab\n cd "+TestTokens.hs256_token+ " cd";
		Body pb = new Body(null,body);
		@SuppressWarnings("unused")
		KeyValuePair result = pb.getJWTFromBody();
		pb.getToken();
		String replaced = pb.replaceTokenImpl(TestTokens.hs256_token_2,body);
		Body pbR = new Body(null,replaced);
		KeyValuePair resultR = pbR.getJWTFromBody();
		assertEquals(resultR.getValue(),TestTokens.hs256_token_2);	
	}
}

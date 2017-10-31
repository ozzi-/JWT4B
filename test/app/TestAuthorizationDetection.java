package app;

import static org.junit.Assert.assertEquals;

import java.util.ArrayList;

import org.junit.Test;

import app.tokenposition.AuthorizationBearerHeader;

public class TestAuthorizationDetection {
	@Test
	public void testAuthValid() {
		ArrayList<String> headers = new ArrayList<>();
		headers.add("GET /jwt/response_cookie.php HTTP/1.1");
		headers.add("Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
		headers.add("Accept-Language: en-US,en;q=0.5");
		headers.add("Authorization: Bearer " + TestTokens.hs256_token);
		headers.add("Connection: close");
		headers.add("Upgrade-Insecure-Requests: 1");
		AuthorizationBearerHeader abh = new AuthorizationBearerHeader(headers,"");
		assertEquals(true,abh.positionFound());
		String result = abh.getToken();
		assertEquals(TestTokens.hs256_token, result);
	}
	
	@Test
	public void testAuthInvalid() {
		ArrayList<String> headers = new ArrayList<>();
		headers.add("GET /jwt/response_cookie.php HTTP/1.1");
		headers.add("Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
		headers.add("Accept-Language: en-US,en;q=0.5");
		headers.add("Authorization: Bearer " + TestTokens.invalid_token);
		headers.add("Connection: close");
		headers.add("Upgrade-Insecure-Requests: 1");
		AuthorizationBearerHeader abh = new AuthorizationBearerHeader(headers,"");
		assertEquals(false,abh.positionFound());
	}
	
	@Test
	public void testAuthInvalid2() {
		ArrayList<String> headers = new ArrayList<>();
		headers.add("GET /jwt/response_cookie.php HTTP/1.1");
		headers.add("Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
		headers.add("Accept-Language: en-US,en;q=0.5");
		headers.add("Authorization: Bearer topsecret123456789!");
		headers.add("Connection: close");
		headers.add("Upgrade-Insecure-Requests: 1");
		AuthorizationBearerHeader abh = new AuthorizationBearerHeader(headers,"");
		assertEquals(false,abh.positionFound());
	}
}

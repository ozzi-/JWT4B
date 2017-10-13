package app;

import static org.junit.Assert.assertEquals;

import java.util.ArrayList;

import org.junit.Test;

import app.tokenposition.Cookie;

public class TestCookieDetection {
	@Test
	public void testCookie() {
		ArrayList<String> headers = new ArrayList<>();
		headers.add("GET /jwt/response_cookie.php HTTP/1.1"); 
		headers.add("Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"); 
		headers.add("Accept-Language: en-US,en;q=0.5"); 
		headers.add("Cookie: token="+TestTokens.hs256_token+"; othercookie=1234"); 
		headers.add("Connection: close");
		headers.add("Upgrade-Insecure-Requests: 1");
		Cookie cookie = new Cookie(headers,"");
		String result = cookie.findJWTInHeaders(headers);
		assertEquals(TestTokens.hs256_token,result);	
	}
	@Test
	public void testCookieTrailingSemiColon() {
		ArrayList<String> headers = new ArrayList<>();
		headers.add("GET /jwt/response_cookie.php HTTP/1.1"); 	 
		headers.add("Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"); 
		headers.add("Accept-Language: en-US,en;q=0.5"); 
		headers.add("Cookie: token="+TestTokens.hs256_token+"; othercookie=1234;"); 
		headers.add("Connection: close");
		headers.add("Upgrade-Insecure-Requests: 1");
		Cookie cookie = new Cookie(headers,"");
		String result = cookie.findJWTInHeaders(headers);
		assertEquals(TestTokens.hs256_token,result);	
	}
	@Test
	public void testCookieLastPositionOfThree() {
		ArrayList<String> headers = new ArrayList<>();
		headers.add("GET /jwt/response_cookie.php HTTP/1.1"); 	 
		headers.add("Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"); 
		headers.add("Accept-Language: en-US,en;q=0.5"); 
		headers.add("Cookie: othercookie=1234; secondcookie=4321; token="+TestTokens.hs256_token+";"); 
		headers.add("Connection: close");
		headers.add("Upgrade-Insecure-Requests: 1");
		Cookie cookie = new Cookie(headers,"");
		String result = cookie.findJWTInHeaders(headers);
		assertEquals(TestTokens.hs256_token,result);	
	}
	@Test
	public void testCookieEmptyOne() {
		ArrayList<String> headers = new ArrayList<>();
		headers.add("GET /jwt/response_cookie.php HTTP/1.1"); 	 
		headers.add("Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"); 
		headers.add("Accept-Language: en-US,en;q=0.5"); 
		headers.add("Cookie: emptycookie=; secondcookie=4321; token="+TestTokens.hs256_token+";"); 
		headers.add("Connection: close");
		headers.add("Upgrade-Insecure-Requests: 1");
		Cookie cookie = new Cookie(headers,"");
		String result = cookie.findJWTInHeaders(headers);
		assertEquals(TestTokens.hs256_token,result);	
	}
	@Test
	public void testCookieEmptyOneSecond() {
		ArrayList<String> headers = new ArrayList<>();
		headers.add("GET /jwt/response_cookie.php HTTP/1.1"); 	 
		headers.add("Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"); 
		headers.add("Accept-Language: en-US,en;q=0.5"); 
		headers.add("Cookie: secondcookie=4321; emptycookie=; token="+TestTokens.hs256_token+";"); 
		headers.add("Connection: close");
		headers.add("Upgrade-Insecure-Requests: 1");
		Cookie cookie = new Cookie(headers,"");
		String result = cookie.findJWTInHeaders(headers);
		assertEquals(TestTokens.hs256_token,result);	
	}
	@Test
	public void testCookieNameOnly() {
		ArrayList<String> headers = new ArrayList<>();
		headers.add("GET /jwt/response_cookie.php HTTP/1.1"); 	 
		headers.add("Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"); 
		headers.add("Accept-Language: en-US,en;q=0.5"); 
		headers.add("Cookie: secondcookie=4321; weirdcookie ; token="+TestTokens.hs256_token+";"); 
		headers.add("Connection: close");
		headers.add("Upgrade-Insecure-Requests: 1");
		Cookie cookie = new Cookie(headers,"");
		String result = cookie.findJWTInHeaders(headers);
		assertEquals(TestTokens.hs256_token,result);	
	}
	@Test
	public void testCookieReversedOrder() {
		ArrayList<String> headers = new ArrayList<>();
		headers.add("GET /jwt/response_cookie.php HTTP/1.1"); 
		headers.add("Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"); 
		headers.add("Accept-Language: en-US,en;q=0.5"); 
		headers.add("Cookie: othercookie=1234; token="+TestTokens.hs256_token); 
		headers.add("Connection: close");
		headers.add("Upgrade-Insecure-Requests: 1");
		Cookie cookie = new Cookie(headers,"");
		String result = cookie.findJWTInHeaders(headers);
		assertEquals(TestTokens.hs256_token,result);	
	}
	@Test
	public void testCookieAlone() {
		ArrayList<String> headers = new ArrayList<>();
		headers.add("GET /jwt/response_cookie.php HTTP/1.1"); 
		headers.add("Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"); 
		headers.add("Accept-Language: en-US,en;q=0.5"); 
		headers.add("Cookie: token="+TestTokens.hs256_token); 
		headers.add("Connection: close");
		headers.add("Upgrade-Insecure-Requests: 1");
		Cookie cookie = new Cookie(headers,"");
		String result = cookie.findJWTInHeaders(headers);
		assertEquals(TestTokens.hs256_token,result);	
	}
	@Test
	public void testCookieInvalidJWT() {
		ArrayList<String> headers = new ArrayList<>();
		headers.add("GET /jwt/response_cookie.php HTTP/1.1"); 
		headers.add("Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"); 
		headers.add("Accept-Language: en-US,en;q=0.5"); 
		headers.add("Cookie: token="+TestTokens.invalid_token); 
		headers.add("Connection: close");
		headers.add("Upgrade-Insecure-Requests: 1");
		Cookie cookie = new Cookie(headers,"");
		String result = cookie.findJWTInHeaders(headers);
		assertEquals(null,result);	
	}
	@Test
	public void testCookieNoJWT() {
		ArrayList<String> headers = new ArrayList<>();
		headers.add("GET /jwt/response_cookie.php HTTP/1.1"); 		 
		headers.add("Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"); 
		headers.add("Accept-Language: en-US,en;q=0.5"); 
		headers.add("Cookie: test=besst"); 
		headers.add("Connection: close");
		headers.add("Upgrade-Insecure-Requests: 1");
		Cookie cookie = new Cookie(headers,"");
		String result = cookie.findJWTInHeaders(headers);
		assertEquals(null,result);	
	}
}

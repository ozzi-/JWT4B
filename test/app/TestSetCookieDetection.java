package app;

import static org.junit.Assert.assertEquals;

import java.util.ArrayList;
import java.util.List;

import org.junit.Test;

import app.helpers.CookieFlagWrapper;
import app.tokenposition.Cookie;

public class TestSetCookieDetection {

	@Test
	public void testCookieReversedOrder() {
		ArrayList<String> headers = new ArrayList<>();
		headers.add("GET /jwt/response_cookie.php HTTP/1.1"); 
		headers.add("Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"); 
		headers.add("Accept-Language: en-US,en;q=0.5"); 
		headers.add("Set-Cookie: token="+TestTokens.hs256_token);
		headers.add("Set-Cookie: test=best");
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
		headers.add("Set-Cookie: token="+TestTokens.invalid_token);
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
	
	
	@Test
	public void testSetCookieGetTokenInvalid() {
		ArrayList<String> headers = new ArrayList<>();
		headers.add("GET /jwt/response_cookie.php HTTP/1.1"); 
		headers.add("Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"); 
		headers.add("Accept-Language: en-US,en;q=0.5"); 
		headers.add("Set-Cookie: token="+TestTokens.invalid_token); 
		headers.add("Connection: close");
		headers.add("Upgrade-Insecure-Requests: 1");
		Cookie cookie = new Cookie(headers,"");
		@SuppressWarnings("unused")
		String result = cookie.findJWTInHeaders(headers);
		assertEquals("",cookie.getToken());
		assertEquals(cookie.positionFound(),false);
	}
		
	@Test
	public void testSetCookieInvalid() {
		ArrayList<String> headers = new ArrayList<>();
		headers.add("GET /jwt/response_cookie.php HTTP/1.1"); 
		headers.add("Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"); 
		headers.add("Accept-Language: en-US,en;q=0.5"); 
		headers.add("Set-Cookie: token="+TestTokens.invalid_token); 
		headers.add("Connection: close");
		headers.add("Upgrade-Insecure-Requests: 1");
		Cookie cookie = new Cookie(headers,"");
		String result = cookie.findJWTInHeaders(headers);
		assertEquals(null,result);	
	}
	
	
	@Test
	public void testSetCookieSemicolon() {
		ArrayList<String> headers = new ArrayList<>();
		headers.add("GET /jwt/response_cookie.php HTTP/1.1"); 
		headers.add("Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"); 
		headers.add("Accept-Language: en-US,en;q=0.5"); 
		headers.add("Set-Cookie: token="+TestTokens.hs256_token+";"); 
		headers.add("Connection: close");
		headers.add("Upgrade-Insecure-Requests: 1");
		Cookie cookie = new Cookie(headers,"");
		String result = cookie.findJWTInHeaders(headers);
		assertEquals(TestTokens.hs256_token,result);	
	}
	
	
	@Test
	public void testSetCookieReplace() {
		List<String> headers = new ArrayList<String>();
		headers.add("GET /jwt/response_cookie.php HTTP/1.1"); 
		headers.add("Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"); 
		headers.add("Accept-Language: en-US,en;q=0.5"); 
		headers.add("Set-Cookie: token="+TestTokens.hs256_token+";"); 
		headers.add("Connection: close");
		headers.add("Upgrade-Insecure-Requests: 1");
		Cookie cookie = new Cookie(headers,"");
		@SuppressWarnings("unused")
		String result = cookie.findJWTInHeaders(headers);
		List<String> replaces = cookie.replaceTokenInHeader(TestTokens.hs256_token_2,headers);
		Cookie cookieR = new Cookie(headers,"");
		String resultR = cookieR.findJWTInHeaders(replaces);
		
		assertEquals(TestTokens.hs256_token_2,resultR);	
	}
	
	@Test
	public void testSetCookie() {
		ArrayList<String> headers = new ArrayList<>();
		headers.add("GET /jwt/response_cookie.php HTTP/1.1"); 
		headers.add("Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"); 
		headers.add("Accept-Language: en-US,en;q=0.5"); 
		headers.add("Set-Cookie: token="+TestTokens.hs256_token); 
		headers.add("Connection: close");
		headers.add("Upgrade-Insecure-Requests: 1");
		Cookie cookie = new Cookie(headers,"");
		String result = cookie.findJWTInHeaders(headers);
		assertEquals(TestTokens.hs256_token,result);	
	}

	@Test
	public void testSetCookieGetToken() {
		ArrayList<String> headers = new ArrayList<>();
		headers.add("GET /jwt/response_cookie.php HTTP/1.1"); 
		headers.add("Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"); 
		headers.add("Accept-Language: en-US,en;q=0.5"); 
		headers.add("Set-Cookie: token="+TestTokens.hs256_token); 
		headers.add("Connection: close");
		headers.add("Upgrade-Insecure-Requests: 1");
		Cookie cookie = new Cookie(headers,"");
		@SuppressWarnings("unused")
		String result = cookie.findJWTInHeaders(headers);
		assertEquals(cookie.getToken(), TestTokens.hs256_token);
	}
	
	@Test
	public void testSetCookieSecureFlag() {
		ArrayList<String> headers = new ArrayList<>();
		headers.add("GET /jwt/response_cookie.php HTTP/1.1"); 
		headers.add("Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"); 
		headers.add("Accept-Language: en-US,en;q=0.5"); 
		headers.add("Set-Cookie: token="+TestTokens.hs256_token+"; expires=Thu, 01-Jan-1970 01:40:00 GMT; Max-Age=0; path=/; secure;"); 
		headers.add("Connection: close");
		headers.add("Upgrade-Insecure-Requests: 1");
		Cookie cookie = new Cookie(headers,"");
		@SuppressWarnings("unused")
		String result = cookie.findJWTInHeaders(headers);
		assertEquals(true,cookie.getcFW().hasSecureFlag());
	}
	
	@Test
	public void testSetCookieHTTPOnlyFlag() {
		ArrayList<String> headers = new ArrayList<>();
		headers.add("GET /jwt/response_cookie.php HTTP/1.1"); 
		headers.add("Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"); 
		headers.add("Accept-Language: en-US,en;q=0.5"); 
		headers.add("Set-Cookie: token="+TestTokens.hs256_token+"; expires=Thu, 01-Jan-1970 01:40:00 GMT; HttpOnly; Max-Age=0; path=/;"); 
		headers.add("Connection: close");
		headers.add("Upgrade-Insecure-Requests: 1");
		Cookie cookie = new Cookie(headers,"");
		@SuppressWarnings("unused")
		String result = cookie.findJWTInHeaders(headers);
		assertEquals(true,cookie.getcFW().hasHttpOnlyFlag());
	}
	
	@Test
	public void testSetCookieBothFlags() {
		ArrayList<String> headers = new ArrayList<>();
		headers.add("GET /jwt/response_cookie.php HTTP/1.1"); 
		headers.add("Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"); 
		headers.add("Accept-Language: en-US,en;q=0.5"); 
		headers.add("Set-Cookie: token="+TestTokens.hs256_token+"; expires=Thu, 01-Jan-1970 01:40:00 GMT; HttpOnly; Max-Age=0; secure; path=/;"); 
		headers.add("Connection: close");
		headers.add("Upgrade-Insecure-Requests: 1");
		Cookie cookie = new Cookie(headers,"");
		@SuppressWarnings("unused")
		String result = cookie.findJWTInHeaders(headers);
		assertEquals(true,cookie.getcFW().hasHttpOnlyFlag());
		assertEquals(true,cookie.getcFW().hasSecureFlag());
	}
	
	@Test
	public void testSetCookieNoFlags() {
		ArrayList<String> headers = new ArrayList<>();
		headers.add("GET /jwt/response_cookie.php HTTP/1.1"); 
		headers.add("Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"); 
		headers.add("Accept-Language: en-US,en;q=0.5"); 
		headers.add("Set-Cookie: token="+TestTokens.hs256_token+"; expires=Thu, 01-Jan-1970 01:40:00 GMT; Max-Age=0; path=/;"); 
		headers.add("Connection: close");
		headers.add("Upgrade-Insecure-Requests: 1");
		Cookie cookie = new Cookie(headers,"");
		@SuppressWarnings("unused")
		String result = cookie.findJWTInHeaders(headers);
		assertEquals(false,cookie.getcFW().hasHttpOnlyFlag());
		assertEquals(false,cookie.getcFW().hasSecureFlag());
	}


}

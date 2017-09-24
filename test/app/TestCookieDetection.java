package app;

import static org.junit.Assert.assertEquals;

import java.util.ArrayList;

import org.junit.Test;

import app.tokenposition.Cookie;

public class TestCookieDetection {
	@Test
	public void testCookie() {
		Cookie cookie = new Cookie();
		ArrayList<String> headers = new ArrayList<>();
		headers.add("GET /jwt/response_cookie.php HTTP/1.1"); 
		headers.add("Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"); 
		headers.add("Accept-Language: en-US,en;q=0.5"); 
		headers.add("Cookie: token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ; othercookie=1234"); 
		headers.add("Connection: close");
		headers.add("Upgrade-Insecure-Requests: 1");
		String result = cookie.findJWTInHeaders(headers);
		assertEquals("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ",result);	
	}
	@Test
	public void testCookieTrailingSemiColon() {
		Cookie cookie = new Cookie();
		ArrayList<String> headers = new ArrayList<>();
		headers.add("GET /jwt/response_cookie.php HTTP/1.1"); 
		 
		headers.add("Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"); 
		headers.add("Accept-Language: en-US,en;q=0.5"); 
		headers.add("Cookie: token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ; othercookie=1234;"); 
		headers.add("Connection: close");
		headers.add("Upgrade-Insecure-Requests: 1");
		String result = cookie.findJWTInHeaders(headers);
		assertEquals("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ",result);	
	}
	@Test
	public void testCookieReversedOrder() {
		Cookie cookie = new Cookie();
		ArrayList<String> headers = new ArrayList<>();
		headers.add("GET /jwt/response_cookie.php HTTP/1.1"); 
		headers.add("Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"); 
		headers.add("Accept-Language: en-US,en;q=0.5"); 
		headers.add("Cookie: othercookie=1234; token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ"); 
		headers.add("Connection: close");
		headers.add("Upgrade-Insecure-Requests: 1");
		String result = cookie.findJWTInHeaders(headers);
		assertEquals("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ",result);	
	}
	@Test
	public void testCookieAlone() {
		Cookie cookie = new Cookie();
		ArrayList<String> headers = new ArrayList<>();
		headers.add("GET /jwt/response_cookie.php HTTP/1.1"); 
		headers.add("Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"); 
		headers.add("Accept-Language: en-US,en;q=0.5"); 
		headers.add("Cookie: token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ"); 
		headers.add("Connection: close");
		headers.add("Upgrade-Insecure-Requests: 1");
		String result = cookie.findJWTInHeaders(headers);
		assertEquals("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ",result);	
	}
	@Test
	public void testCookieInvalidJWT() {
		Cookie cookie = new Cookie();
		ArrayList<String> headers = new ArrayList<>();
		headers.add("GET /jwt/response_cookie.php HTTP/1.1"); 
		headers.add("Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"); 
		headers.add("Accept-Language: en-US,en;q=0.5"); 
		headers.add("Cookie: token=INVALIDiOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ"); 
		headers.add("Connection: close");
		headers.add("Upgrade-Insecure-Requests: 1");
		String result = cookie.findJWTInHeaders(headers);
		assertEquals(null,result);	
	}
	@Test
	public void testCookieNoJWT() {
		Cookie cookie = new Cookie();
		ArrayList<String> headers = new ArrayList<>();
		headers.add("GET /jwt/response_cookie.php HTTP/1.1"); 		 
		headers.add("Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"); 
		headers.add("Accept-Language: en-US,en;q=0.5"); 
		headers.add("Cookie: test=besst"); 
		headers.add("Connection: close");
		headers.add("Upgrade-Insecure-Requests: 1");
		String result = cookie.findJWTInHeaders(headers);
		assertEquals(null,result);	
	}
}

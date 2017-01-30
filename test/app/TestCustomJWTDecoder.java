package app;

import static org.junit.Assert.*;

import org.junit.Test;

public class TestCustomJWTDecoder {

	
	public static final String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ";

	@Test
	public void testIfTokenCanbeDecoded() {
		CustomJWTDecoder reConstructedToken = new CustomJWTDecoder(token);
		assertEquals(token, reConstructedToken.getToken());
	}

}

package app;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.Test;

import app.tokenposition.AuthorizationBearerHeader;

 class TestFindTokenInHeader {
	 
	 String jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.KMUFsIDTnFmyG3nMiGM6H9FNFUROf3wh7SmqJp-QV30";

	@Test
	void testCustomAuthKeyword() {
		AuthorizationBearerHeader authorizationBearerHeader = new AuthorizationBearerHeader(null, true);
		Optional<String> containedJwt = authorizationBearerHeader.containsJwt("X-ABC "+jwt, List.of("Bearer","bearer","BEARER"));
		assertThat(containedJwt).isPresent();
		assertThat(containedJwt.get()).startsWith(jwt);
	}
	
	@Test
	void testRegularAuthKeyword() {
		AuthorizationBearerHeader authorizationBearerHeader = new AuthorizationBearerHeader(null, true);
		Optional<String> containedJwt = authorizationBearerHeader.containsJwt("Bearer "+jwt, List.of("Bearer","bearer","BEARER"));
		assertThat(containedJwt).isPresent();
		assertThat(containedJwt.get()).startsWith(jwt);
	}
	
	@Test
	void testCustomAuthKeywordNegative() {
		AuthorizationBearerHeader authorizationBearerHeader = new AuthorizationBearerHeader(null, true);
		Optional<String> containedJwt = authorizationBearerHeader.containsJwt("X-ABC foo.bar", List.of("Bearer","bearer","BEARER"));
		assertThat(containedJwt).isEmpty();
	}
	
	@Test
	void testRegularAuthKeywordNegative() {
		AuthorizationBearerHeader authorizationBearerHeader = new AuthorizationBearerHeader(null, true);
		Optional<String> containedJwt = authorizationBearerHeader.containsJwt("Bearer foo.bar", List.of("Bearer","bearer","BEARER"));
		assertThat(containedJwt).isEmpty();
	}
}

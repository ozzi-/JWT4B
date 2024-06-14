package app.tokenposition;

import java.util.List;
import java.util.Optional;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpMessage;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import model.CustomJWToken;

// finds and replaces JWT's in authorization headers
public class AuthorizationBearerHeader extends ITokenPosition {

	private Optional<String> headerContainsJwt;
	private String headerName;
	private String headerKeyword;

	public AuthorizationBearerHeader(HttpMessage httpMessage, boolean isRequest) {
		super(httpMessage, isRequest);
	}

	public boolean positionFound() {
		try {
			for (HttpHeader header : httpMessage.headers()) {
				headerContainsJwt = containsJwt(header.value(), List.of("Bearer","bearer","BEARER"));
				if (headerContainsJwt.isPresent()) {
					headerName = header.name();
					headerKeyword = headerContainsJwt.get();
					String jwtValue = header.value().substring(headerContainsJwt.get().length() + 1);
					if (CustomJWToken.isValidJWT(jwtValue)) {
						this.token = jwtValue;
						return true;
					}
				}
			}
		} catch (Exception ignored) {
			System.out.println(ignored.getMessage());
		}
		return false;
	}

	private Optional<String> containsJwt(String header, List<String> jwtKeywords) {
		for (String keyword : jwtKeywords) {
			if (header.startsWith(keyword)) {
				String jwt = header.replace(keyword, "").trim();
				if (CustomJWToken.isValidJWT(jwt)) {
					return Optional.of(keyword);
				}
			}
		}
		return Optional.empty();
	}

	@Override
	public HttpRequest getRequest() {
		HttpRequest httpRequest = HttpRequest.httpRequest(httpMessage.toString());
		if (headerContainsJwt.isEmpty()) {
			return httpRequest;
		}
		return httpRequest.withUpdatedHeader(headerName, headerKeyword + " " + token);
	}

	@Override
	public HttpResponse getResponse() {
		HttpResponse httpResponse = HttpResponse.httpResponse(httpMessage.toString());
		if (headerContainsJwt.isEmpty()) {
			return httpResponse;
		}
		return httpResponse.withUpdatedHeader(headerName, headerKeyword + " " + token);
	}
}

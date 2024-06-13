package app.tokenposition;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import model.CustomJWToken;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpMessage;

// finds and replaces JWT's in authorization headers
public class AuthorizationBearerHeader extends ITokenPosition {

	private static final String AUTHORIZATION_HEADER = "Authorization";
	private static final String BEARER_PREFIX = "Bearer";

	public AuthorizationBearerHeader(HttpMessage httpMessage, boolean isRequest) {
		super(httpMessage, isRequest);
	}

	public boolean positionFound() {
		try {
			HttpHeader authorizationHeader = httpMessage.header(AUTHORIZATION_HEADER);

			if (authorizationHeader != null) {
				boolean isBearer = authorizationHeader.value().regionMatches(true, 0, BEARER_PREFIX, 0, BEARER_PREFIX.length());
				if (isBearer) {
					String jwtValue = authorizationHeader.value().substring(BEARER_PREFIX.length() + 1);
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

	@Override
	public HttpRequest getRequest() {
		HttpRequest httpRequest = HttpRequest.httpRequest(httpMessage.toString());
		return httpRequest.withUpdatedHeader(AUTHORIZATION_HEADER, BEARER_PREFIX + " " + token);
	}

	@Override
	public HttpResponse getResponse() {
		HttpResponse httpResponse = HttpResponse.httpResponse(httpMessage.toString());
		return httpResponse.withUpdatedHeader(AUTHORIZATION_HEADER, BEARER_PREFIX + " " + token);
	}
}

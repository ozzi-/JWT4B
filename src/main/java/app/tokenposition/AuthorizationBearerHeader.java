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

	private Optional<String> containedJwt;
	private String headerName;
	private String headerKeyword;

	public AuthorizationBearerHeader(HttpMessage httpMessage, boolean isRequest) {
		super(httpMessage, isRequest);
	}

	public boolean positionFound() {
		try {
			for (HttpHeader header : httpMessage.headers()) {
				containedJwt = containsJwt(header.value(), List.of("Bearer","bearer","BEARER"));
				if (containedJwt.isPresent()) {
					headerName = header.name();
					this.token = containedJwt.get();
					return true;
				}
			}
		} catch (Exception ignored) {
			System.out.println(ignored.getMessage());
		}
		return false;
	}

	public Optional<String> containsJwt(String headerValue, List<String> jwtKeywords) {
		for (String keyword : jwtKeywords) {
			boolean usesCustomAuthType = !headerValue.startsWith(keyword) && (headerValue.contains(" ") && headerValue.contains("ey"));
			if (usesCustomAuthType) {
					keyword = headerValue.split(" ")[0];
			}
			String potentialJwt = headerValue.replace(keyword, "").trim();
			if (CustomJWToken.isValidJWT(potentialJwt)) {
				headerKeyword = keyword;
				return Optional.of(potentialJwt);
			}
		}
		if(headerValue.toLowerCase().startsWith("ey") || containsExactlyTwoDots(headerValue)) {
			String potentialJwt = headerValue.trim();
			if (CustomJWToken.isValidJWT(potentialJwt)) {
				headerKeyword = "";
				return Optional.of(potentialJwt);
			}
		}
		return Optional.empty();
	}

	@Override
	public HttpRequest getRequest() {
		HttpRequest httpRequest = HttpRequest.httpRequest(httpMessage.toString());
		if (containedJwt.isEmpty()) {
			return httpRequest;
		}
		return httpRequest.withUpdatedHeader(headerName, headerKeyword + needsSpace(headerKeyword) + token);
	}

	@Override
	public HttpResponse getResponse() {
		HttpResponse httpResponse = HttpResponse.httpResponse(httpMessage.toString());
		if (containedJwt.isEmpty()) {
			return httpResponse;
		}
		return httpResponse.withUpdatedHeader(headerName, headerKeyword + needsSpace(headerKeyword) + token);
	}
	

	private String needsSpace(String headerKeyword) {
		return headerKeyword.equals("")?"":" ";
	}

	
	private boolean containsExactlyTwoDots(String str) {
	    int firstDotIndex = str.indexOf('.');
	    if (firstDotIndex == -1) {
	        return false;
	    }
	    int secondDotIndex = str.indexOf('.', firstDotIndex + 1);
	    if (secondDotIndex == -1) {
	        return false;
	    }
	    return str.indexOf('.', secondDotIndex + 1) == -1;
	}
}

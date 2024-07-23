package app.tokenposition;

import java.util.List;

import app.helpers.CookieFlagWrapper;
import app.helpers.KeyValuePair;
import app.helpers.TokenChecker;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpMessage;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

//finds and replaces JWT's in cookies
public class Cookie extends ITokenPosition {

	private static final String SET_COOKIE_HEADER = "Set-Cookie";
	private static final String COOKIE_HEADER = "Cookie";

	private CookieFlagWrapper cFW;
	private KeyValuePair cookieHeader;

	public Cookie(HttpMessage httpMessage, boolean isRequest) {
		super(httpMessage, isRequest);
	}

	@Override
	public boolean positionFound() {
		try {
			List<HttpHeader> headers = this.httpMessage.headers();

			cookieHeader = getJWTInCookieHeader(headers);
			if (cookieHeader != null) {
				token = cookieHeader.getValue();
				return true;
			}
		} catch (Exception ignored) {
			//
		}

		return false;
	}

	@Override
	public HttpRequest getRequest() {
		HttpRequest httpRequest = (HttpRequest) httpMessage;
		return httpRequest.withParameter(HttpParameter.cookieParameter(cookieHeader.getName(), token));
	}

	@Override
	public HttpResponse getResponse() {
		return HttpResponse.httpResponse(replaceTokenImpl(this.token, httpMessage.toString()));
	}

	private String replaceTokenImpl(String newToken, String httpMessageAsString) {
		String newMessage = httpMessageAsString;
		List<HttpHeader> headers = this.httpMessage.headers();

		KeyValuePair cookieJWT = getJWTInCookieHeader(headers);
		if (cookieJWT != null) {
			newMessage = httpMessageAsString.replace(cookieJWT.getValue(), newToken);
		}

		return newMessage;
	}

	// finds the first jwt in the set-cookie or cookie header(s)
	public KeyValuePair getJWTInCookieHeader(List<HttpHeader> headers) {
		cFW = new CookieFlagWrapper(false, false, false);

		for (HttpHeader httpHeader : headers) {
			if (httpHeader.name().regionMatches(true, 0, SET_COOKIE_HEADER, 0, SET_COOKIE_HEADER.length())) {
				String setCookieValue = httpHeader.value();
				if (setCookieValue.length() > 1 && setCookieValue.contains("=")) { // sanity check
					int nameMarkerPos = setCookieValue.indexOf("=");
					String name = setCookieValue.substring(0,nameMarkerPos);
					String value = setCookieValue.substring(nameMarkerPos+1);
					int flagMarker = value.indexOf(";");
					if (flagMarker != -1) {
						value = value.substring(0, flagMarker);
						cFW = new CookieFlagWrapper(true, setCookieValue.toLowerCase().contains("; secure"), setCookieValue.toLowerCase().contains("; httponly"));
					} else {
						cFW = new CookieFlagWrapper(true, false, false);
					}
					if (TokenChecker.isValidJWT(value)) {
						return new KeyValuePair(name, value);
					}
				}
			}

			if (httpHeader.name().regionMatches(true, 0, COOKIE_HEADER, 0, COOKIE_HEADER.length())) {
				String cookieHeaderValue = httpHeader.value();
		        if (cookieHeaderValue != null && !cookieHeaderValue.isEmpty()) {
		            String[] pairs = cookieHeaderValue.split(";\\s*");
		            for (String pair : pairs) {
		                String[] parts = pair.split("=", 2);
		                if (parts.length == 2) {
		                    String name = parts[0].trim();
		                    String value = parts[1].trim();
							if (TokenChecker.isValidJWT(value)) {
								return new KeyValuePair(name, value);
							}
		                }
		            }
		        }
			}
		}
		return null;
	}

	
	@Override
	public CookieFlagWrapper getcFW() {
		return this.cFW;
	}
}

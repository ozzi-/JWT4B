package app.tokenposition;

import java.util.List;
import java.util.regex.Pattern;

import app.helpers.KeyValuePair;
import app.helpers.Output;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpMessage;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import org.apache.commons.lang.StringUtils;

import app.helpers.CookieFlagWrapper;
import app.helpers.TokenChecker;

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
				String cookie = httpHeader.value();
				if (cookie.length() > 1 && cookie.contains("=")) {
					String name = cookie.split(Pattern.quote("="))[0];
					String value = cookie.split(Pattern.quote("="))[1];
					int flagMarker = value.indexOf(";");
					if (flagMarker != -1) {
						value = value.substring(0, flagMarker);
						cFW = new CookieFlagWrapper(true, cookie.toLowerCase().contains("; secure"), cookie.toLowerCase().contains("; httponly"));
					} else {
						cFW = new CookieFlagWrapper(true, false, false);
					}
					TokenChecker.isValidJWT(value);
					if (TokenChecker.isValidJWT(value)) {
						return new KeyValuePair(name, value);
					}
				}
			}

			if (httpHeader.name().regionMatches(true, 0, COOKIE_HEADER, 0, COOKIE_HEADER.length())) {
				String cookieHeader = httpHeader.value();
				cookieHeader = cookieHeader.endsWith(";") ? cookieHeader : cookieHeader + ";";
				int from = 0;
				int index = cookieHeader.indexOf(";");
				int cookieCount = StringUtils.countMatches(cookieHeader, ";");
				for (int i = 0; i < cookieCount; i++) {
					String cookie = cookieHeader.substring(from, index);
					cookie = cookie.replace(";", "");
					String[] cvp = cookie.split(Pattern.quote("="));
					String name = cvp[0];
					String value = cvp.length == 2 ? cvp[1] : "";

					if (TokenChecker.isValidJWT(value)) {
						return new KeyValuePair(name, value);
					}
					from = index;
					index = cookieHeader.indexOf(";", index + 1);
					if (index == -1) {
						index = cookieHeader.length();
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

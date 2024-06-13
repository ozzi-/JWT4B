package app.tokenposition;

import java.util.Arrays;
import java.util.List;

import app.helpers.CookieFlagWrapper;
import app.helpers.Output;

import burp.api.montoya.http.message.HttpMessage;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import model.Strings;

public abstract class ITokenPosition {

	protected boolean isRequest;
	protected HttpMessage httpMessage;
	protected String token;

	protected ITokenPosition(HttpMessage httpMessage, boolean isRequest) {
		this.httpMessage = httpMessage;
		this.isRequest = isRequest;
	}

	public abstract boolean positionFound();

	public abstract HttpRequest getRequest();

	public abstract HttpResponse getResponse();

	private static CookieFlagWrapper cookieFlagWrap;

	public static ITokenPosition findTokenPositionImplementation(HttpMessage httpMessage, boolean isRequest) {
		List<Class<? extends ITokenPosition>> implementations = Arrays.asList(AuthorizationBearerHeader.class, PostBody.class, Body.class, Cookie.class);

		for (Class<? extends ITokenPosition> implClass : implementations) {
			try {
				ITokenPosition impl = (ITokenPosition) implClass.getConstructors()[0].newInstance(httpMessage, isRequest);

				if (impl.positionFound()) {
					if (impl instanceof Cookie) {
						cookieFlagWrap = ((Cookie) impl).getcFW();
					} else {
						cookieFlagWrap = new CookieFlagWrapper(false, false, false);
					}
					return impl;
				}
			} catch (Exception e) {
				// sometimes 'isEnabled' is called in order to build the views
				// before an actual request / response passes through - in that case
				// it is not worth reporting
				if (!e.getMessage().equals("Request cannot be null") && !e.getMessage().equals("1")) {
					Output.outputError(e.getMessage());
				}
				return null;
			}
		}
		return null;
	}

	public String getToken() {
		return (this.token != null) ? this.token : "";
	}

	public void replaceToken(String newToken) {
		this.token = newToken;
	}

	public void addHeader(String name, String value) {
		// add header
		if (isRequest) {
			HttpRequest request = (HttpRequest) httpMessage;
			httpMessage = request.withAddedHeader(name, value);
		} else {
			HttpResponse response = (HttpResponse) httpMessage;
			httpMessage = response.withAddedHeader(name, value);
		}
	}

	public void cleanJWTHeaders() {
		// remove headers that start with Strings.JWTHeaderPrefix)
		if (isRequest) {
			HttpRequest request = (HttpRequest) httpMessage;
			httpMessage = request.withRemovedHeader(Strings.JWT_HEADER_PREFIX);
		} else {
			HttpResponse response = (HttpResponse) httpMessage;
			httpMessage = response.withRemovedHeader(Strings.JWT_HEADER_PREFIX);
		}
	}

	public CookieFlagWrapper getcFW() {
		return cookieFlagWrap;
	}

}

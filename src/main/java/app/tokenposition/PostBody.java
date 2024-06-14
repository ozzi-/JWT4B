package app.tokenposition;

import java.util.List;

import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;

import burp.api.montoya.http.message.HttpMessage;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import app.helpers.Config;
import app.helpers.TokenChecker;

public class PostBody extends ITokenPosition {

	private HttpParameter httpParameter;

	public PostBody(HttpMessage httpMessage, boolean isRequest) {
		super(httpMessage, isRequest);
	}

	@Override
	public boolean positionFound() {
		if (isRequest) {
			httpParameter = getJWTFromPostBody();
			if (httpParameter != null) {
				token = httpParameter.value();
				return true;
			}
		}
		return false;
	}

	private HttpParameter getJWTFromPostBody() {
		if (isRequest) {
			HttpRequest httpRequest = (HttpRequest) httpMessage;
			List<ParsedHttpParameter> parsedHttpParameters = httpRequest.parameters(HttpParameterType.BODY);

			return parsedHttpParameters.stream().filter(parameter -> Config.tokenKeywords.contains(parameter.name()) && TokenChecker.isValidJWT(parameter.value())).findFirst().orElse(null);
		}

		return null;
	}

	@Override
	public HttpRequest getRequest() {
		HttpRequest httpRequest = (HttpRequest) httpMessage;

		return httpRequest.withParameter(HttpParameter.bodyParameter(httpParameter.name(), token));
	}

	@Override
	public HttpResponse getResponse() {
		return (HttpResponse) httpMessage;
	}
}

package app.controllers;

import app.helpers.Config;
import app.helpers.SecretFinder;
import app.tokenposition.ITokenPosition;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;

// This controller handles the highlighting of entries in the HTTP history tab
public class HighLightController implements HttpHandler {

	private String validSecret;
	
	@Override
	public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
			ITokenPosition tokenPosition = ITokenPosition.findTokenPositionImplementation(requestToBeSent, true);
			boolean containsJWT = tokenPosition != null;
			if (containsJWT) {

				SecretFinder sfh = new SecretFinder(tokenPosition, requestToBeSent);
				this.validSecret = sfh.collectSecrets().stream()
						.filter(sfh::checkSecret)
						.findFirst()
						.orElse(null);

				updateAnnotations(requestToBeSent.annotations());
			}else {
				this.validSecret = null;
			}

			return RequestToBeSentAction.continueWith(requestToBeSent);
		}

	@Override
	public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
		boolean containsJWT = ITokenPosition.findTokenPositionImplementation(responseReceived, false) != null;
		if (containsJWT) {
			updateAnnotations(responseReceived.annotations());
		}
		return ResponseReceivedAction.continueWith(responseReceived);
	}

	private void updateAnnotations(Annotations annotations) {
		if (!Config.interceptComment.isEmpty()) {
			annotations.setNotes(Config.interceptComment);
		}
		if (!Config.highlightColor.equals("None")) {
			annotations.setHighlightColor(HighlightColor.highlightColor(Config.highlightColor));
		}
		
		if(this.validSecret != null) {
			annotations.setNotes(Config.SecretFoundInterceptComment.concat(this.validSecret));
			annotations.setHighlightColor(HighlightColor.highlightColor(Config.SecretFoundHighlightColor));
		}
	}
}

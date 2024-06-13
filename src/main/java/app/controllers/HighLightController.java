package app.controllers;

import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.http.handler.*;

import app.helpers.Config;
import app.tokenposition.ITokenPosition;

// This controller handles the highlighting of entries in the HTTP history tab
public class HighLightController implements HttpHandler {

	@Override
	public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
		boolean containsJWT = ITokenPosition.findTokenPositionImplementation(requestToBeSent, true) != null;
		if (containsJWT) {
			updateAnnotations(requestToBeSent.annotations());
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
	}
}

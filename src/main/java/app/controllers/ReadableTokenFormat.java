package app.controllers;

import static com.eclipsesource.json.WriterConfig.PRETTY_PRINT;

import static org.apache.commons.lang.StringUtils.isBlank;

import com.eclipsesource.json.Json;
import com.eclipsesource.json.JsonValue;

import app.helpers.Output;
import gui.JWTInterceptTab;
import model.CustomJWToken;

public class ReadableTokenFormat {

	ReadableTokenFormat() {

	}

	private static final String NEW_LINE = System.getProperty("line.separator");
	private static final String TITTLE_HEADERS = "Headers = ";
	private static final String TITLE_PAYLOAD = NEW_LINE + NEW_LINE + "Payload = ";
	private static final String TITLE_SIGNATURE = NEW_LINE + NEW_LINE + "Signature = ";

	public static String getReadableFormat(CustomJWToken token) {

		return TITTLE_HEADERS + jsonBeautify(token.getHeaderJson()) + TITLE_PAYLOAD + jsonBeautify(token.getPayloadJson()) + TITLE_SIGNATURE + "\"" + token.getSignature() + "\"";
	}

	public static String jsonBeautify(String input) {
		if (isBlank(input)) {
			return "";
		}

		try {
			JsonValue value = Json.parse(input);
			return value.toString(PRETTY_PRINT);
		} catch (RuntimeException e) {
			Output.outputError("Exception beautifying JSON: " + e.getMessage());
			return input;
		}
	}

	public static CustomJWToken getTokenFromView(JWTInterceptTab jwtST) {
		String header = jwtST.getJwtHeaderArea().getText();
		String payload = jwtST.getJwtPayloadArea().getText();
		String signature = jwtST.getJwtSignatureArea().getText();
		return new CustomJWToken(header, payload, signature);
	}

	public static class InvalidTokenFormat extends Exception {

		private static final long serialVersionUID = 1L;

		public InvalidTokenFormat(String message) {
			super(message);
		}
	}
}

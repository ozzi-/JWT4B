package app.tokenposition;

import java.util.List;
import java.util.regex.Pattern;
import com.eclipsesource.json.Json;
import com.eclipsesource.json.JsonObject;
import org.apache.commons.lang.StringUtils;

import app.helpers.ConsoleOut;
import app.helpers.KeyValuePair;
import app.helpers.TokenCheck;

public class Body extends ITokenPosition {
	private String token;
	private boolean found = false;
	private String body;

	public Body(List<String> headersP, String bodyP) {
		body = bodyP;
	}

	@Override
	public boolean positionFound() {
		KeyValuePair postJWT = getJWTFromBody();
		if (postJWT != null) {
			found = true;
			token = postJWT.getValue();
			return true;
		}
		return false;
	}

	public KeyValuePair getJWTFromBody() {
		KeyValuePair ret;
		if ((ret = getJWTFromBodyWithParameters()) != null) {
			return ret;
		} else if ((ret = getJWTFromBodyWithJson()) != null) {
			return ret;
		} else {
			return getJWTFromBodyWithoutParametersOrJSON();
		}
	}

	private KeyValuePair getJWTFromBodyWithoutParametersOrJSON() {
		String split[] = StringUtils.split(body);
		for (String strg : split) {
			if (TokenCheck.isValidJWT(strg)) {
				return new KeyValuePair("", strg);
			}
		}
		return null;
	}
 
	private KeyValuePair getJWTFromBodyWithJson() {
		JsonObject obj;
		try {
			if(body.length()<2){
				return null;
			}
			obj = Json.parse(body).asObject();
		} catch (Exception e) {
			ConsoleOut.output("Can't parse claims - " + e.getMessage());
			return null;
		}
		return lookForJwtInJsonObject(obj);
	}

	private KeyValuePair lookForJwtInJsonObject(JsonObject object) {
		KeyValuePair rec;
		for (String name : object.names()) {
			if (object.get(name).isString()) {
				if (TokenCheck.isValidJWT(object.get(name).asString())) {
					return new KeyValuePair(name, object.get(name).asString().trim());
				}
			} else if (object.get(name).isObject()) {
				if ((rec = lookForJwtInJsonObject(object.get(name).asObject())) != null) {
					return rec;
				}
			}
		}
		return null;
	}


	private KeyValuePair getJWTFromBodyWithParameters() {

		int from = 0;
		int index = body.indexOf("&") == -1 ? body.length() : body.indexOf("&");
		int parameterCount = StringUtils.countMatches(body, "&") + 1;

		for (int i = 0; i < parameterCount; i++) {
			String parameter = body.substring(from, index);
			parameter = parameter.replace("&", "");

			String[] parameterSplit = parameter.split(Pattern.quote("="));
			if (parameterSplit.length > 1) {
				String name = parameterSplit[0];
				String value = parameterSplit[1];
				if (TokenCheck.isValidJWT(value)) {
					return new KeyValuePair(name, value);
				}

				from = index;
				index = body.indexOf("&", index + 1);
				if (index == -1) {
					index = body.length();
				}
			}
		}
		return null;
	}

	@Override
	public String getToken() {
		return found ? token : "";
	}

	@Override
	public byte[] replaceToken(String newToken) {
		body = replaceTokenImpl(newToken, body);
		return getHelpers().buildHttpMessage(getHeaders(), body.getBytes());
	}

	public String replaceTokenImpl(String newToken, String body) {
		boolean replaced = false;
		KeyValuePair postJWT = getJWTFromBody();
		if (postJWT != null) {
			body = body.replace(postJWT.getValue(), newToken);
		}
		if (!replaced) {
			ConsoleOut.output("Could not replace token in post body.");
		}
		return body;
	}

}

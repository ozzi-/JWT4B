package app.helpers;

import org.apache.commons.lang.StringUtils;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;

public class TokenChecker {
	
	private TokenChecker() {
		
	}

	public static final String JWT_ALLOWED_CHARS_REGEXP = "[A-Za-z0-9+/=_-]+";

	public static boolean isValidJWT(String jwt) {
		int dotCount = StringUtils.countMatches(jwt, ".");
		if (dotCount != 2) {
			return false;
		}

		jwt = jwt.trim();
		if (StringUtils.contains(jwt, " ")) {
			return false;
		}

		for (String part : StringUtils.split(jwt, ".")) {
			if (!part.matches(JWT_ALLOWED_CHARS_REGEXP)) {
				return false;
			}
		}

		try {
			DecodedJWT decoded = JWT.decode(jwt);
			decoded.getAlgorithm();
			return true;
		} catch (Exception ignored) {
			// ignored
		}

		return false;
	}
}

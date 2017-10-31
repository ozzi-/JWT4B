package app.helpers;

import org.apache.commons.lang.StringUtils;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;

public class TokenCheck {
	public static boolean isValidJWT(String jwt) {
		if (StringUtils.countMatches(jwt, ".") != 2) {
			return false;
		}
		try {
			DecodedJWT decoded = JWT.decode(jwt);
			decoded.getAlgorithm();
			return true;
		} catch (Exception exception) {}
		return false;
	}
}

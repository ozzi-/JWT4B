package app.tokenposition;

import java.util.List;
import java.util.regex.Pattern;

import org.apache.commons.lang.StringUtils;

import app.helpers.TokenCheck;

public class Cookie extends ITokenPosition {

	private boolean found;
	private String token;
	
	@Override
	public boolean positionFound() {
		List<String> headers = getHeaders();
		String jwt = findJWTInHeaders(headers);
		if(jwt!=null) {
			found=true;
			token=jwt;
			return true;			
		}
		return false;
	}

	// finds the first jwt in the set-cookie or cookie header(s)
	public String findJWTInHeaders(List<String> headers) {
		for (String header : headers) {
			if(header.startsWith("Set-Cookie: ")) {
				String cookie = header.replace("Set-Cookie: ", "");
				if(cookie.length()>1 && cookie.contains("=")) {
					String value = cookie.split(Pattern.quote("="))[1];
					value=value.endsWith(";")?value.substring(0, value.length()-1):value;
					if(TokenCheck.isValidJWT(value)) {
						// TODO remove debug output
						System.out.println("found in set cookie");
						return value;
					}
				}
			}
			if(header.startsWith("Cookie: ")) {
				String cookieHeader = header.replace("Cookie: ","");
				cookieHeader=cookieHeader.endsWith(";")?cookieHeader.substring(0, cookieHeader.length()-1):cookieHeader;
				int from = 0;
				int index = cookieHeader.indexOf(";")==-1?cookieHeader.length():cookieHeader.indexOf(";");
				int cookieCount = StringUtils.countMatches(cookieHeader, "=");

				for (int i = 0; i < cookieCount; i++) {
					String cookie = cookieHeader.substring(from, index);
					cookie = cookie.replace(";", "");
					String value = cookie.split(Pattern.quote("="))[1];
					if(TokenCheck.isValidJWT(value)) {
						// TODO remove debug output
						System.out.println("found in cookie");
						return value;
					}
					from = index;
					index = cookieHeader.indexOf("&", index + 1);
					if(index == -1){
						index = cookieHeader.length();
					}
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
		// TODO implement replace
		return null;
	}
}

package app.tokenposition;

import java.util.List;
import java.util.regex.Pattern;

import org.apache.commons.lang.StringUtils;

import app.helpers.CookieFlagWrapper;
import app.helpers.TokenCheck;

public class Cookie extends ITokenPosition {

	private boolean found;
	private String token;
	private List<String> headers;
	private CookieFlagWrapper cFW = null;
	
	public Cookie(List<String> headersP, String bodyP) {
		headers=headersP;
	}
	
	@Override
	public boolean positionFound() {
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
		// defaulting
		cFW = new CookieFlagWrapper(false, false, false); 

		for (String header : headers) {
			if(header.startsWith("Set-Cookie: ")) {
				String cookie = header.replace("Set-Cookie: ", "");
				if(cookie.length()>1 && cookie.contains("=")) {
					String value = cookie.split(Pattern.quote("="))[1];
					int flagMarker = value.indexOf(";");
					if(flagMarker!=-1){
						String flags = value.substring(flagMarker);
						value=value.substring(0, flagMarker);
						cFW = new CookieFlagWrapper(true, flags.contains("secure"), flags.contains("HttpOnly")); 
					}else{
						cFW = new CookieFlagWrapper(true, false, false);
					}
					TokenCheck.isValidJWT(value);
					if(TokenCheck.isValidJWT(value)) {
						found=true;
						token=value;
						return value;
					}
				}
			}
			if(header.startsWith("Cookie: ")) {
				String cookieHeader = header.replace("Cookie: ","");
				cookieHeader=cookieHeader.endsWith(";")?cookieHeader:cookieHeader+";";
				int from = 0;
				int index = cookieHeader.indexOf(";");
				int cookieCount = StringUtils.countMatches(cookieHeader, ";");
				for (int i = 0; i < cookieCount; i++) {
					String cookie = cookieHeader.substring(from, index);
					cookie = cookie.replace(";", "");
					String value = cookie.split(Pattern.quote("="))[1];
					if(TokenCheck.isValidJWT(value)) {
						found=true;
						token=value;
						return value;
					}
					from = index;
					index = cookieHeader.indexOf(";", index + 1);
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
		headers = replaceTokenInHeader(newToken, headers);
		return getHelpers().buildHttpMessage(headers, getBody());		
	}

	public List<String> replaceTokenInHeader(String newToken, List<String> headers) {
		int i=0;
		Integer pos=null;
		String replacedHeader="";
		
		for (String header : headers) {
			if(header.contains(token)){
				pos = i;
				replacedHeader = header.replace(token, newToken);
			}
			i++;
		}
		if(pos != null){
			headers.set(pos, replacedHeader);
		}
		return headers;
	}

	public CookieFlagWrapper getcFW(){
		return cFW;
	}
}

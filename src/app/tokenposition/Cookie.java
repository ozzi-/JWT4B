package app.tokenposition;

import java.util.List;
import java.util.regex.Pattern;
import org.apache.commons.lang.StringUtils;
import app.helpers.TokenCheck;

//finds and replaces JWT's in cookies
public class Cookie extends ITokenPosition {

	private static final String SET_COOKIE_HEADER = "Set-Cookie: ";
	private static final String COOKIE_HEADER = "Cookie: ";

	private boolean found;
	private String token;
	private List<String> headers;
	private boolean secureFlag;
	private boolean httpOnlyFlag;

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
		for (String header : headers) {
			if(header.startsWith(SET_COOKIE_HEADER)) {
				String cookie = header.replace(SET_COOKIE_HEADER, "");
				if(cookie.length()>1 && cookie.contains("=")) {
					String value = cookie.split(Pattern.quote("="))[1];
					int flagMarker = value.indexOf(";");

					if (flagMarker!=-1){
						value=value.substring(0, flagMarker);
						secureFlag = cookie.toLowerCase().contains("; secure");
						httpOnlyFlag = cookie.toLowerCase().contains("; httponly");
					}

					TokenCheck.isValidJWT(value);
					if(TokenCheck.isValidJWT(value)) {
						found=true;
						token=value;
						return value;
					}
				}
			}
			if(header.startsWith(COOKIE_HEADER)) {
				String cookieHeader = header.replace(COOKIE_HEADER,"");
				cookieHeader=cookieHeader.endsWith(";")?cookieHeader:cookieHeader+";";
				int from = 0;
				int index = cookieHeader.indexOf(";");
				int cookieCount = StringUtils.countMatches(cookieHeader, ";");
				for (int i = 0; i < cookieCount; i++) {
					String cookie = cookieHeader.substring(from, index);
					cookie = cookie.replace(";", "");
					String[] cvp = cookie.split(Pattern.quote("="));
					String value = cvp.length==2?cvp[1]:"";
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

	public boolean hasSecureFlag() {
		return secureFlag;
	}

	public boolean hasHttpOnlyFlag() {
		return httpOnlyFlag;
	}

	@Override
	public String toHTMLString() {
		StringBuilder html = new StringBuilder();

		html.append("<html><div style=\"width:300px; max-height: 50px;\">");

		String secureFlagHtml = secureFlag
				? "<span style=\"color: green\">Secure Flag set.</span><br>"
				: "<span style=\"color: red\">No secure flag set. Token may be transmitted by HTTP.</span><br>";
		html.append(secureFlagHtml);

		String httpOnlyHtml = httpOnlyFlag
				? "<span style=\"color: green\">HttpOnly Flag set.</span>"
				: "<span style=\"color: red\">No HttpOnly flag set. Token may accessed by JavaScript (XSS).</span>";
		html.append(httpOnlyHtml);

		html.append("</div></html>");

		return html.toString();
	}
}

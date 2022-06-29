package app.tokenposition;

import java.util.List;
import java.util.regex.Pattern;

import org.apache.commons.lang.StringUtils;

import app.helpers.CookieFlagWrapper;
import app.helpers.TokenChecker;

//finds and replaces JWT's in cookies
public class Cookie extends ITokenPosition {

  public static final String SET_COOKIE_HEADER = "Set-Cookie: ";
  public static final String COOKIE_HEADER = "Cookie: ";
  private boolean found;
  private String token;
  private List<String> headers;
  private CookieFlagWrapper cFW = null;

  public Cookie(List<String> headers, String body) {
    this.headers = headers;
  }

  @Override
  public boolean positionFound() {
    String jwt = findJWTInHeaders(headers);
    if (jwt != null) {
      found = true;
      token = jwt;
      return true;
    }
    return false;
  }

  // finds the first jwt in the set-cookie or cookie header(s)
  public String findJWTInHeaders(List<String> headers) {
    // defaulting
    cFW = new CookieFlagWrapper(false, false, false);

    for (String header : headers) {
      if (header.startsWith(SET_COOKIE_HEADER)) {
        String cookie = header.replace(SET_COOKIE_HEADER, "");
        if (cookie.length() > 1 && cookie.contains("=")) {
          String value = cookie.split(Pattern.quote("="))[1];
          int flagMarker = value.indexOf(";");
          if (flagMarker != -1) {
            value = value.substring(0, flagMarker);
            cFW = new CookieFlagWrapper(true, cookie.toLowerCase().contains("; secure"),
                cookie.toLowerCase().contains("; httponly"));
          } else {
            cFW = new CookieFlagWrapper(true, false, false);
          }
          TokenChecker.isValidJWT(value);
          if (TokenChecker.isValidJWT(value)) {
            found = true;
            token = value;
            return value;
          }
        }
      }
      if (header.startsWith(COOKIE_HEADER)) {
        String cookieHeader = header.replace(COOKIE_HEADER, "");
        cookieHeader = cookieHeader.endsWith(";") ? cookieHeader : cookieHeader + ";";
        int from = 0;
        int index = cookieHeader.indexOf(";");
        int cookieCount = StringUtils.countMatches(cookieHeader, ";");
        for (int i = 0; i < cookieCount; i++) {
          String cookie = cookieHeader.substring(from, index);
          cookie = cookie.replace(";", "");
          String[] cvp = cookie.split(Pattern.quote("="));
          String value = cvp.length == 2 ? cvp[1] : "";
          if (TokenChecker.isValidJWT(value)) {
            found = true;
            token = value;
            return value;
          }
          from = index;
          index = cookieHeader.indexOf(";", index + 1);
          if (index == -1) {
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
    int i = 0;
    Integer pos = null;
    String replacedHeader = "";

    for (String header : headers) {
      if (header.contains(token)) {
        pos = i;
        replacedHeader = header.replace(token, newToken);
      }
      i++;
    }
    if (pos != null) {
      headers.set(pos, replacedHeader);
    }
    return headers;
  }

  public CookieFlagWrapper getcFW() {
    return cFW;
  }
}

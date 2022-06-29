package app.tokenposition;

import java.util.List;

import app.helpers.Config;
import model.CustomJWToken;

// finds and replaces JWT's in authorization headers
public class AuthorizationBearerHeader extends ITokenPosition {

  private String selectedKeyword;
  private Integer headerIndex;
  private final List<String> headers;

  public AuthorizationBearerHeader(List<String> headers, String ignored) {
    this.headers = headers;
  }

  public boolean positionFound() {
    for (int counter = 0; counter < headers.size(); counter++) {
      if (headerContainsKeyWordAndIsJWT(headers.get(counter), Config.jwtKeywords)) {
        this.headerIndex = counter;
        return true;
      }
    }
    return false;
  }

  private boolean headerContainsKeyWordAndIsJWT(String header, List<String> jwtKeywords) {
    for (String keyword : jwtKeywords) {
      if (header.startsWith(keyword)) {
        String jwt = header.replace(keyword, "").trim();
        if (CustomJWToken.isValidJWT(jwt)) {
          this.selectedKeyword = keyword;
          return true;
        }
      }
    }
    return false;
  }

  public String getToken() {
    if (this.headerIndex == null) {
      return "";
    }
    return headers.get(this.headerIndex).substring(this.selectedKeyword.length() + 1);
  }

  public byte[] replaceToken(String newToken) {
    if (positionFound()) { // updating headerIndex
      headers.set(this.headerIndex, this.selectedKeyword + " " + newToken);
    }
    return getHelpers().buildHttpMessage(headers, getBody());
  }
}

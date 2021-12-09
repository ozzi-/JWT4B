package app.helpers;

import java.awt.Color;

public class CookieFlagWrapper {

  private final boolean secureFlag;
  private final boolean httpOnlyFlag;
  private final boolean isCookie;

  public CookieFlagWrapper(boolean isCookie, boolean secureFlag, boolean httpOnlyFlag) {
    this.isCookie = isCookie;
    this.secureFlag = secureFlag;
    this.httpOnlyFlag = httpOnlyFlag;
  }

  public boolean isCookie() {
    return isCookie;
  }

  public boolean hasHttpOnlyFlag() {
    if (isCookie) {
      return httpOnlyFlag;
    }
    return false;
  }

  public boolean hasSecureFlag() {
    if (isCookie) {
      return secureFlag;
    }
    return false;
  }

  public ColorString toColorString() {
    if (!isCookie) {
      return new ColorString("", Color.WHITE);
    }
    Color color;
    String returnString = "";
    if (!hasSecureFlag()) {
      color = Color.RED;
      returnString += "No secure flag set. Token may be transmitted by HTTP.\r\n";
    } else {
      color = Color.GREEN;
      returnString += "Secure Flag set.\r\n";
    }
    if (!hasHttpOnlyFlag()) {
      color = Color.RED;
      returnString += "No HttpOnly flag set. Token may accessed by JavaScript (XSS).";
    } else {
      color = Color.GREEN;
      returnString += "HttpOnly Flag set.";
    }
    returnString += "</div></html>";
    return new ColorString(returnString, color);
  }

}

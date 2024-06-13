package model;

import java.util.List;

public class TimeClaim {

  private final String date;
  private final long unixTimestamp;
  private final boolean valid;
  private final String claim;
  private final boolean canBeValid;

  public TimeClaim(String claim, String date, long unixTimestamp, boolean valid) {
    this.claim = claim;
    this.date = date;
    this.unixTimestamp = unixTimestamp;
    this.valid = valid;
    this.canBeValid = true;
  }

  public TimeClaim(String claim, String date, long unixTimestamp) {
    this.claim = claim;
    this.date = date;
    this.unixTimestamp = unixTimestamp;
    this.valid = true;
    this.canBeValid = false;
  }

  public String getClaimName() {
    return claim;
  }

  public String getDate() {
    return date;
  }
  
  public boolean canBeValid() {
    return canBeValid;
  }

  public boolean isValid() {
    return valid;
  }

  public static String getTimeClaimsAsHTML(List<TimeClaim> tcl) {
    StringBuilder timeClaimSB = new StringBuilder();
    timeClaimSB.append("<html>");
    if (tcl != null && !tcl.isEmpty()) {
      for (TimeClaim timeClaim : tcl) {
        timeClaimSB.append("<b>" + timeClaim.getClaimName() + (timeClaim.canBeValid() ?
            "</b> check " + (timeClaim.isValid() ?
                "<span style=\"color: green\">passed</span>" :
                "<span style=\"color: red\">failed</span>") :
            "</b>") + " - " + timeClaim.getDate() + "<br>");
      }
    }
    timeClaimSB.append("</html>");
    return timeClaimSB.toString();
  }
}

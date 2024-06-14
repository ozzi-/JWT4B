package model;

import java.util.List;

import lombok.Data;
import lombok.RequiredArgsConstructor;

@Data
@RequiredArgsConstructor
public class TimeClaim {

	private final String claim;
	private final String date;
	private final long unixTimestamp;
	private final boolean valid;
	private final boolean canBeValid;

	public static String getTimeClaimsAsHTML(List<TimeClaim> tcl) {
		StringBuilder timeClaimSB = new StringBuilder();
		timeClaimSB.append("<html>");
		if (tcl != null && !tcl.isEmpty()) {
			for (TimeClaim timeClaim : tcl) {
				String resultString = timeClaim.isValid() ? "<span style=\"color: green\">passed</span>" : "<span style=\"color: red\">failed</span>";
				timeClaimSB.append("<b>" + timeClaim.getClaim() + (timeClaim.isCanBeValid() ? "</b> check " + resultString : "</b>") + " - " + timeClaim.getDate() + "<br>");
			}
		}
		timeClaimSB.append("</html>");
		return timeClaimSB.toString();
	}
}

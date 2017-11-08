package model;

import java.util.List;

public class TimeClaim {
	private String date;
	private long unixTimestamp;
	private boolean valid;
	private String claim;
	private boolean canBeValid;
	
	public TimeClaim(String claim, String date, long unixTimestamp, boolean valid) {
		this.claim = claim;
		this.date=date;
		this.unixTimestamp=unixTimestamp;
		this.valid=valid;
		this.canBeValid = true;
	}
	
	public TimeClaim(String claim, String date, long unixTimestamp) {
		this.claim = claim;
		this.date=date;
		this.unixTimestamp=unixTimestamp;
		this.valid = true;
		this.canBeValid = false;
	}

	public String getClaimName() {
		return claim;
	}

	public String getDate() {
		return date;
	}

	public long getUnixTimestamp() {
		return unixTimestamp;
	}
	public boolean canBeValid() {
		return canBeValid;
	}
	public boolean isValid() {
		return valid;
	}
	public static String getTimeClaimsAsText(List<TimeClaim> tcl){
		String timeClaimString = "<html>";
		for (TimeClaim timeClaim : tcl) {
			timeClaimString+="<b>"+timeClaim.getClaimName()+
					(timeClaim.canBeValid()?"</b> check "+(timeClaim.isValid()?"<span style=\"color: green\">passed</span>":"<span style=\"color: red\">failed</span>"):"</b>")+
					" - "+timeClaim.getDate()+"<br>";
		}
		return timeClaimString+"</html>";
	}
}

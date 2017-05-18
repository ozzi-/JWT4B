package app.helpers;

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
}

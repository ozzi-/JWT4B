package app.helpers;

public class CookieFlagWrapper {
	private boolean secureFlag;
	private boolean httpOnlyFlag;
	private boolean isCookie;

	public CookieFlagWrapper(boolean isCookie, boolean secureFlag, boolean httpOnlyFlag) {
		this.isCookie = isCookie;
		this.secureFlag = secureFlag;
		this.httpOnlyFlag = httpOnlyFlag;
	}
	
	public boolean isCookie(){
		return isCookie;
	}

	public boolean hasHttpOnlyFlag() {
		if(isCookie){
			return httpOnlyFlag;			
		}
		return false;
	}

	public boolean hasSecureFlag() {
		if(isCookie){
			return secureFlag;			
		}
		return false;
	}
	
	public String toHTMLString(){
		if(!isCookie){
			return "";
		}
		String returnString="<html><div style=\"width:300px; max-height: 50px;\">";
		if(!hasSecureFlag()){
			returnString+="<span style=\"color: red\">No secure flag set. Token may be transmitted by HTTP.</span><br>";
		}else{
			returnString+="<span style=\"color: green\">Secure Flag set.</span><br>";
		}
		if(!hasHttpOnlyFlag()){
			returnString+="<span style=\"color: red\">No HttpOnly flag set. Token may accessed by JavaScript (XSS).</span>";
		}else{
			returnString+="<span style=\"color: green\">HttpOnly Flag set.</span>";
		}
		returnString+="</div></html>";
		return returnString;
	}

}

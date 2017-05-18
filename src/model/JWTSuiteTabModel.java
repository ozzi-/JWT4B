package model;

import java.awt.Color;
import java.util.List;

import app.helpers.TimeClaim;

public class JWTSuiteTabModel {
	private String jwtInput;
	private String jwtKey;
	private Color jwtSignatureColor;
	private String jwtJSON;
	private String verificationLabel;
	private List<TimeClaim> tcl;
	
	public String getJwtInput() {
		return jwtInput;
	}
	public void setJwtInput(String jwtInput) {
		this.jwtInput = jwtInput;
	}
	public String getJwtKey() {
		return jwtKey;
	}
	public void setJwtKey(String jwtKey) {
		this.jwtKey = jwtKey;
	}
	public Color getJwtSignatureColor() {
		return jwtSignatureColor;
	}
	public void setJwtSignatureColor(Color jwtSignatureColor) {
		this.jwtSignatureColor = jwtSignatureColor;
	}
	public String getJwtJSON() {
		return jwtJSON;
	}
	public void setJwtJSON(String jwtJSON) {
		this.jwtJSON = jwtJSON;
	}
	public void setVerificationLabel(String label) {
		this.verificationLabel = label;
	}
	public String getVerificationLabel() {
		return this.verificationLabel;
	}
	public void setTimeClaims(List<TimeClaim> tcl) {
		this.tcl=tcl;
	}
	public String getTimeClaimsAsText(){
		String timeClaimString = "<html>";
		for (TimeClaim timeClaim : tcl) {
			timeClaimString+="<b>"+timeClaim.getClaimName()+
					(timeClaim.canBeValid()?"</b> check "+(timeClaim.isValid()?"<span style=\"color: green\">passed</span>":"<span style=\"color: red\">failed</span>"):"</b>")+
					" - "+timeClaim.getDate()+"<br>";
		}
		return timeClaimString+"</html>";
	}
}
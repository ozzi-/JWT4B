package model;

import java.awt.Color;

public class JWTSuiteTabModel {
	private String jwtInput;
	private String jwtKey;
	private Color jwtSignatureColor;
	private String jwtJSON;
	private String verificationLabel;
	
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
}
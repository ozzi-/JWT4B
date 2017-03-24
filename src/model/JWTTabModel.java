package model;

import java.awt.Color;

import app.helpers.Settings;

public class JWTTabModel {
	private String key="";
	private String keyLabel="";
	private int hashCode;
	private String verificationLabel="";
	private Color verificationColor=Settings.colorUndefined;
	private String jwt;
	private String jwtJSON;

	public JWTTabModel(){
	}
	
	public JWTTabModel(String keyValue, byte[] content) {
		this.key = keyValue;
		this.hashCode = new String(content).hashCode();
	}

	@Override
	public boolean equals(Object otherObj) {
		if (otherObj instanceof JWTTabModel) {
			JWTTabModel otherViewState = (JWTTabModel) otherObj;
			return (otherViewState.getHashCode() == this.getHashCode());
		}
		return false;
	}

	public String getKey() {
		return key;
	}

	public int getHashCode() {
		return hashCode;
	}

	public void setKeyValueAndHash(String keyValue, int hashCode) {
		this.key = keyValue;
		this.hashCode = hashCode;
	}

	public void setVerificationResult(String verificationResult) {
		this.verificationLabel = verificationResult;
	}

	public String getKeyLabel() {
		return keyLabel;
	}

	public void setKeyLabel(String keyLabel) {
		this.keyLabel = keyLabel;
	}

	public String getVerificationLabel() {
		return verificationLabel;
	}

	public void setVerificationLabel(String verificationLabel) {
		this.verificationLabel = verificationLabel;
	}

	public Color getVerificationColor() {
		return verificationColor;
	}

	public void setVerificationColor(Color verificationColor) {
		this.verificationColor = verificationColor;
	}

	public void setKey(String key) {
		this.key = key;
	}

	public void setHashCode(int hashCode) {
		this.hashCode = hashCode;
	}

	public void setJWT(String token) {
		this.jwt=token;		
	}

	public String getJWT() {
		return jwt;
	}

	public String getJWTJSON() {
		return jwtJSON;
	}

	public void setJWTJSON(String readableFormat) {
		jwtJSON=readableFormat;
	}

}

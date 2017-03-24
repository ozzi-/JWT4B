package model;

import java.awt.Color;

public class JWTMessageEditorModel {
	private String keyValue;
	private int hashCode;
	private String verificationResult;
	private Color verificationResultColor;

	public JWTMessageEditorModel(String keyValue, byte[] content) {
		this.keyValue = keyValue;
		this.hashCode = new String(content).hashCode();
	}

	@Override
	public boolean equals(Object otherObj) {
		if (otherObj instanceof JWTMessageEditorModel) {
			JWTMessageEditorModel otherViewState = (JWTMessageEditorModel) otherObj;
			return (otherViewState.getHashCode() == this.getHashCode());
		}
		return false;
	}

	public String getKeyValue() {
		return keyValue;
	}

	public int getHashCode() {
		return hashCode;
	}

	public void setKeyValueAndHash(String keyValue, int hashCode) {
		this.keyValue = keyValue;
		this.hashCode = hashCode;
	}

	public void setVerificationResult(String verificationResult) {
		this.verificationResult = verificationResult;
		
	}

	public void setVerificationResultColor(Color verificationResultColor) {
		this.verificationResultColor = verificationResultColor;
	}

	public String getVerificationResult() {
		return verificationResult;
	}

	public Color getVerificationResultColor() {
		return verificationResultColor;
	}

}

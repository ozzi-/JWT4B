package app.helpers;

import java.awt.Color;

public class ViewState {
	private String keyValue;
	private int hashCode;
	private String verificationResult;
	private Color verificationResultColor;

	public ViewState(String keyValue, byte[] content) {
		this.keyValue = keyValue;
		this.hashCode = new String(content).hashCode();
	}

	@Override
	public boolean equals(Object otherObj) {
		if (otherObj instanceof ViewState) {
			ViewState otherViewState = (ViewState) otherObj;
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

package gui;

import java.awt.Color;

import javax.swing.JPanel;

public abstract class JWTTab extends JPanel{
	private static final long serialVersionUID = 1L;
	public abstract String getKeyValue();
	public abstract void setVerificationResult(String value);
	public abstract void setKeyValue(String value);
	public abstract void setVerificationResultColor(Color verificationResultColor);
}

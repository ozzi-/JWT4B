package app.helpers;

import java.awt.Color;

import javax.swing.JButton;

public class Settings {
	public static final String tabname = "JWT4B";
	public static final String extensionName = "JWT4Burp";

	public static final Boolean output = true;
	
	public static final Color colorValid = Color.GREEN;
	public static final Color colorInvalid = Color.RED;
	public static final Color colorUndefined = new JButton().getBackground();
	public static final Color colorProblemInvalid = Color.YELLOW;
}

package app;

import java.awt.Color;

public class Settings {
	public static final String tabname = "JWT4B";
	public static final String extensionName = "JWT4Burp";
	public static final String contextMenuString = "Send selected text to JWT4B Tab to decode";

	public static final String tokenStateOriginal = "Original";
	public static String tokenStateUpdated = "Token updated";
	
	public static String verificationValid = "Signature verified";
	public static String verificationInvalidKey = "Invalid key";
	public static String verificationWrongKey = "Invalid Signature / wrong key";
	
	
	public static final Boolean output = true;
	
	public static Color colorValid = Color.GREEN;
	public static Color colorInvalid = Color.RED;
	public static Color colorUndefined = Color.GRAY;
	public static Color colorProblemInvalid = Color.YELLOW;
}

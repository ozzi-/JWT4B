package app;

import java.awt.Color;

public class Settings {
	public static final String tabname = "JWT4B";
	public static final String extensionName = "JWT4Burp";
	public static final String contextMenuString = "Send selected text to JWT4B Tab to decode";

	public static final String tokenStateOriginal = "Original";
	public static final String tokenStateUpdated = "Token updated";
	
	public static final String verificationValid = "Signature verified";
	public static final String verificationInvalidKey = "Invalid key";
	public static final String verificationWrongKey = "Invalid Signature / wrong key";
	
	
	public static final Boolean output = true;
	
	public static final Color colorValid = Color.GREEN;
	public static final Color colorInvalid = Color.RED;
	public static final Color colorUndefined = Color.GRAY;
	public static final Color colorProblemInvalid = Color.YELLOW;
}

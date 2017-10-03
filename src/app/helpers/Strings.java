package app.helpers;

public class Strings {
	public static final String contextMenuString = "Send selected text to JSON Web Tokens Tab to decode";

	public static final String tokenStateOriginal = "Original";
	public static final String tokenStateUpdated = "Token updated";

	public static final String acceptChanges = "Accept Changes";
	public static final String recalculateSignature = "Recalculate Signature";
	public static final String originalToken = "Original Token";
	public static final String updateAlgorithmSignature = "Update Algorithm / Signature";
	public static final String decodedJWT = "Decoded JWT";	
	public static final String enterJWT = "Enter JWT";
	
	public static final String verificationValid = "Signature verified";
	public static final String verificationInvalidKey = "Invalid key";
	public static final String verificationWrongKey = "Invalid Signature / wrong key / claim failed";

	public static final String interceptRecalculationKey = "Secret / Key for Signature recalculation:";

	public static final String dontModify = "Do not automatically modify signature";
	public static final String keepOriginalSignature ="Keep original signature";
	public static final String randomKey = "Sign with random key pair";
	public static final String enterSecretKey="Enter Secret / Key";

	public static final String dontModifyToolTip ="The signature will be taken straight out of the editable field to the left";
	public static final String recalculateSignatureToolTip = "<html>The signature will be recalculated depending<br> on the content and algorithm set</html>";
	public static final String keepOriginalSignatureToolTip = "The signature originally sent will be preserved and sent unchanged";
	public static final String randomKeyToolTip = "<html>The signature will be recalculated depending<br>on the content and algorithm set<br>by a random signature / key</html>";

	public static final String creditTitle ="JSON Web Tokens - About";

	public static final String creditText ="<html><h2>About JSON Web Tokens</h2>JSON Web Tokens is developed by Oussama Zgheb (zgheb.com) and Matthias Vetsch.<br><br>"
			+ "All self-written code, excluding the BURP Extender classes, auth0 java-jwt library (MIT), Apache Commons Lang (apache license 2.0) and the RSyntaxTextArea library <br>(https://github.com/bobbylight/RSyntaxTextArea/blob/master/src/main/dist/<br>RSyntaxTextArea.License.txt) use the"
			+ " GPL3 licence<br>https://www.gnu.org/licenses/gpl-3.0.html.<br><br>"
			+ "Credits:"
			+ "<ul>"
			+ "<li>RSyntaxTextArea &nbsp;- https://github.com/bobbylight/RSyntaxTextArea</li>"
			+ "<li>java-jwt &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;- https://github.com/auth0/java-jwt</li>"
			+ "<li>Compass Security AG, for providing development time<br>https://compass-security.com</li>"
			+ "</ul>"
			+ "</html>";

	public static final String JWTHeaderPrefix = "JWT4B: ";
	public static final String JWTHeaderInfo = JWTHeaderPrefix+"The following headers are added automatically, in order to log the keys";


}

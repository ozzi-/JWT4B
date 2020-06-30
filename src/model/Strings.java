package model;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;

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
	public static final String verificationInvalidKey = "Invalid Key";
	public static final String verificationInvalidSignature = "Cannot verify Signature";
	public static final String verificationInvalidClaim = "Not all Claims accepted";
	public static final String verificationError = "Invalid Signature / wrong key / claim failed";

	public static final String interceptRecalculationKey = "Secret / Key for Signature recalculation:";

	public static final String dontModify = "Do not automatically modify signature";
	public static final String keepOriginalSignature ="Keep original signature";
	public static final String randomKey = "Sign with random key pair";
	public static final String enterSecretKey="Enter Secret / Key";
	public static final String chooseSignature = "Load Secret / Key from File";

	
	public static final String dontModifyToolTip ="The signature will be taken straight out of the editable field to the left";
	public static final String recalculateSignatureToolTip = "<html>The signature will be recalculated depending<br> on the content and algorithm set</html>";
	public static final String keepOriginalSignatureToolTip = "The signature originally sent will be preserved and sent unchanged";
	public static final String randomKeyToolTip = "<html>The signature will be recalculated depending<br>on the content and algorithm set<br>by a random signature / key</html>";
	public static String chooseSignatureToolTip = "Load the secret / key from a file chosen by your OS file picker";

	public static final String creditTitle ="JSON Web Tokens - About";

	public static final String JWTHeaderPrefix = "JWT4B: ";
	public static final String JWTHeaderInfo = JWTHeaderPrefix+"The following headers are added automatically, in order to log the keys";


	public static String filePathToString(String filePath) {
		StringBuilder contentBuilder = new StringBuilder();
		try (BufferedReader br = new BufferedReader(new FileReader(filePath))) {

			String sCurrentLine;
			while ((sCurrentLine = br.readLine()) != null) {
				contentBuilder.append(sCurrentLine).append(System.lineSeparator());
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
		String result = contentBuilder.toString();
		return result.substring(0,result.length()-System.lineSeparator().length());
	}
}

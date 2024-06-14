package model;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;

public class Strings {

	private Strings() {
	}

	public static final String CONTEXT_MENU_STRING = "Send selected text to JSON Web Tokens Tab to decode";

	public static final String ORIGINAL_TOKEN_STATE = "Original";
	public static final String UPDATED_TOKEN_STATE = "Token updated";

	public static final String ACCEPT_CHANGES = "Accept Changes";
	public static final String RECALC_SIGNATURE = "Recalculate Signature";
	public static final String ORIGINAL_TOKEN = "Original Token";
	public static final String UPDATE_ALGO_SIG = "Update Algorithm / Signature";
	public static final String NO_SECRET_PROVIDED = "No secret provided";
	public static final String DECODED_JWT = "Decoded JWT";
	public static final String ENTER_JWT = "Enter JWT";

	public static final String VALID_VERFICIATION = "Signature verified";
	public static final String INVALID_KEY_VERIFICATION = "Invalid Key";
	public static final String INVALID_SIGNATURE_VERIFICATION = "Cannot verify Signature";
	public static final String INVALID_CLAIM_VERIFICATION = "Not all Claims accepted";
	public static final String GENERIC_ERROR_VERIFICATION = "Invalid Signature / wrong key / claim failed";

	public static final String RECALC_KEY_INTERCEPT = "Secret / Key for Signature recalculation:";

	public static final String DONT_MODIFY = "Do not automatically modify signature";
	public static final String KEEP_ORIG_SIG = "Keep original signature";
	public static final String RANDOM_KEY = "Sign with random key pair";
	public static final String ENTER_SECRET_KEY = "Enter Secret / Key";
	public static final String CHOOSE_SIG = "Load Secret / Key from File";

	public static final String DONT_MODIFY_TT = "The signature will be taken straight out of the editable field to the left";
	public static final String RECALC_SIG_TT = "<html>The signature will be recalculated depending<br> on the content and algorithm set</html>";
	public static final String KEEP_ORIG_SIG_TT = "The signature originally sent will be preserved and sent unchanged";
	public static final String RANDOM_KEY_TT = "<html>The signature will be recalculated depending<br>on the content and algorithm set<br>by a random signature / key</html>";
	public static final String CHOOSE_SIG_TT = "Load the secret / key from a file chosen by your OS file picker";

	public static final String CREDIT_TITLE = "JSON Web Tokens - About";

	public static final String JWT_HEADER_PREFIX = "JWT4B";
	public static final String JWT_HEADER_INFO = "The following headers are added automatically, in order to log the keys";

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
		return result.substring(0, result.length() - System.lineSeparator().length());
	}
}

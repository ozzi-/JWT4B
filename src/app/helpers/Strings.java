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
			+ "<li>Brainloop, for providing broader token support<br>https://www.brainloop.com/</li>"
			+ "</ul>"
			+ "</html>";

	public static final String JWTHeaderPrefix = "JWT4B: ";
	public static final String JWTHeaderInfo = JWTHeaderPrefix+"The following headers are added automatically, in order to log the keys";

	public static String publicKey 	= "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuNCJ/1Tawe8DUIbQDxjR"
									+"r+bVSoIdcOjJm5wskbMUjHopTWERzLo65yLPjCVcRudQ8DNJIs3yb+hzxi0b8uyK"
									+"XK6nYTaxdwtRN61NMgI/ecNYw1A3nMLRJ4KetLCUqCehVV+OavJqwGXb0k4OhJu7"
									+"VefLD9PxOQxLd/MxJLMTChqYYQWY069oNTB9uRaBRLwcEv3i8uiM3HAdx4di0FZL"
									+"HN5yAt6Zq7TR53CUDSI74q/AH4zeuo+D/UscVTq2bInfJmN3NdA6XqPdjnu6DtT7"
									+"VQZif+06sFXgnoieuUaeRE0Jn8ZY72hljToFZmsLUPPhTSzmFTgko4+MGnS29w1r"
									+"bQIDAQAB";
	
	public static String privateKey	= "MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQC40In/VNrB7wNQ"
									+"htAPGNGv5tVKgh1w6MmbnCyRsxSMeilNYRHMujrnIs+MJVxG51DwM0kizfJv6HPG"
									+"LRvy7IpcrqdhNrF3C1E3rU0yAj95w1jDUDecwtEngp60sJSoJ6FVX45q8mrAZdvS"
									+"Tg6Em7tV58sP0/E5DEt38zEksxMKGphhBZjTr2g1MH25FoFEvBwS/eLy6IzccB3H"
									+"h2LQVksc3nIC3pmrtNHncJQNIjvir8AfjN66j4P9SxxVOrZsid8mY3c10Dpeo92O"
									+"e7oO1PtVBmJ/7TqwVeCeiJ65Rp5ETQmfxljvaGWNOgVmawtQ8+FNLOYVOCSjj4wa"
									+"dLb3DWttAgMBAAECggEBALF/J2ngNxEW2loWf/Bf59NGoQakHF56VFZtEakFEvEv"
									+"ykcUuSGkojmmhyqUHyHBu0xWFSGmJfcwizCD1lnir6f/3aVR//LTHbeZa5Bh9FCf"
									+"Orqqah7WREXr/zyOctdk6F+0HHW+SKRrr0k1yl+1qaABtFaJOR2PH1Qebs5OZjTG"
									+"XvKtm5H7G4FeNPDjprCKB5vRiWPY5F3sRJOFp8TwkH5qbirgZh0KJiYuJMq9Qtzj"
									+"RHYjzALOSWldpqb8Xzcx7lHZbF8gNv3zeRJRJWTYATq8KVaZ3fs0mv9z37MPRC1A"
									+"S9v4ylrwXsAviWvn21Q6E1jrxOxZfAhkoA2aLtFMr4kCgYEA68yc8mupFsRCwcfC"
									+"hauAExibU2lCmW1ImcWxGLQR0dVPyaEPlecwKxvdetWs7BPaxqogKppB71gsxXYA"
									+"SUntgwj1f7zXxo4rdSZv20B09eASo+I8qZpfDZWR1oM7HjXR40lWELtQhzD0QDQC"
									+"UmQtCpVGgyheqPsrQntCeM5LEisCgYEAyKXD93Onevtg6K2GWmnIgCP8+PRvu9kY"
									+"W+3yhN0BGzmJrVSlD6uw0SAsA7awd54Qs00gGcWoztDm7V+YHDcYy3oOzwip4Yw2"
									+"S3kUPewupySLm1VrDBMdXVp1sQH/I5DE3B4c5OxgdCmiX+7hLkXBBjpOqbHS+2bs"
									+"Ps9qnO2M5McCgYAhj84G8yvuAaE+05/sRqzECwyQorrH+7YJrQm36mle5G2m1TXS"
									+"sEU63Yx4n1EtiOXqwOwzJCGeX35/3HvN8qfLrsrCk65ipHmrAv2Ix3PeSzZb/SeF"
									+"PGOrG07WqXcQpbhqEVYeq4qas20QdlaeQ4PlrbmLkYNnqdhObhzX9QTaYQKBgQDD"
									+"a9/fpL8cIrWSKV/Ps3PaijKa7sfcd2coMiqgiPfI4lNbhDN3fcsrA2CbBVX+Su8N"
									+"EzMOptrxA7nGu/JUmL0HgQvnTRLYYE2JWJYEcYJGvGtUkO8/xWY2RCKYkc9Dfn6d"
									+"vJ57wFV5Dgvdz7V18e47+JIg6NcKkIXL7wxxZ1RwhQKBgQDd4nlMdJue4zA7hO2Y"
									+"GxUqX+ALVY6ikZ/SBOQIDrnI9aixwXYQ3t3Nwjim73/0uiLXLOpO92dBSym7GeSP"
									+"YqWZhkyQ8C05tDyGvDI5b7bVmD1pxmnhG9sOktrkDVkOsYUnAhRwCgmuExkoeGWP"
									+"vUt+85cmMpJfHHqbrb5FLqTeXQ==";
}

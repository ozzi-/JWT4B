package app;

import java.util.Arrays;
import java.util.List;

public class JWTFinder {
	// TODO add possible other ways
	private static List<String> jwtKeywords = Arrays.asList("Authorization: Bearer","Todo other");
    /**
    * @param headers list containing the headers
    * @return the JWT header if found, else NULL
    */	
	public static String findJWTInHeaders(List<String> headers){
		for (String header : headers) {
			for (String jwtKeyword : jwtKeywords){
				int position = header.indexOf(jwtKeyword);
				if (position != -1) {
					int startOfJWT = position+1+jwtKeyword.length();
					String jwt = header.substring(startOfJWT);
					return jwt;
				}
			}
		}
		return null;
	}
}
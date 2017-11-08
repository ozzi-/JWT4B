package app.tokenposition;

import java.util.Arrays;
import java.util.List;

import app.helpers.CustomJWToken;

public class AuthorizationBearerHeader extends ITokenPosition {

	private static List<String> jwtKeywords = Arrays.asList("Authorization: Bearer");
	private String selectedKeyword;
	private Integer headerIndex;
	private List<String> headers;
	
	public AuthorizationBearerHeader(List<String> headers, String bodyP) {
		this.headers=headers;
	}
	
	public boolean positionFound() {
		for(int counter = 0; counter<headers.size(); counter++) { 
			if(headerContainsaKeyWordAndIsJWT(headers.get(counter), jwtKeywords)) {
				this.headerIndex = counter;
				return true;
			}
		}
		return false;
	}
	
	private boolean headerContainsaKeyWordAndIsJWT(String header, List<String> jwtKeywords) {
		for(String keyword : jwtKeywords){
			if(header.startsWith(keyword)){ 
				String jwt = header.replace(keyword, "").trim();
				if(CustomJWToken.isValidJWT(jwt)){
					this.selectedKeyword = keyword;
					return true;	
				}
			}
		}
		return false;
	}

	public String getToken() {
		if(this.headerIndex == null) { 
			return "";
		}
		return headers.get(this.headerIndex).substring(this.selectedKeyword.length()+1);
	}

	public byte[] replaceToken(String newToken) {
		if(positionFound()){ // updating headerIndex
			headers.set(this.headerIndex, this.selectedKeyword + " " + newToken);			
		}
		return getHelpers().buildHttpMessage(headers, getBody());
	}
}

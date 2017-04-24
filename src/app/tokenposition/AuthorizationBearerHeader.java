package app.tokenposition;

import java.util.Arrays;
import java.util.List;

public class AuthorizationBearerHeader extends ITokenPosition {

	private static List<String> jwtKeywords = Arrays.asList("Authorization: Bearer");
	private String selectedKeyword;
	private Integer headerIndex;

	public boolean positionFound() {
		List<String> headers = getHeaders();
		for(int counter = 0; counter<headers.size(); counter++) { 
			if(headerContainsaKeyWord(headers.get(counter), jwtKeywords)) { 
				this.headerIndex = counter;
				return true;
			}
		}
		return false;
	}

	private boolean headerContainsaKeyWord(String header, List<String> jwtKeywords) {
		for(String keyword : jwtKeywords) { 
			if(header.startsWith(keyword)) { 
				this.selectedKeyword = keyword;
				return true;
			}
		}
		return false;
	}

	public String getToken() {
		if(this.headerIndex == null) { 
			return "";
		}
		return this.getHeaders().get(this.headerIndex).substring(this.selectedKeyword.length()+1);
	}

	public byte[] replaceToken(String newToken) {
		List<String> newheaders = getHeaders();
		newheaders.set(this.headerIndex, this.selectedKeyword + " " + newToken);
		return getHelpers().buildHttpMessage(newheaders, getBody());
	}
}

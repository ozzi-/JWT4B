package app.tokenposition;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;

import org.apache.commons.lang.StringUtils;

import app.helpers.ConsoleOut;
import app.helpers.KeyValuePair;

public class PostBody extends ITokenPosition {
	private String token;
	private boolean found = false;
	private List<String> tokenKeyWords = Arrays
			.asList("id_token", "ID_TOKEN", "access_token", "token");

	@Override
	public boolean positionFound() {
		if(isRequest){
			String body = new String(getBody());
			List<KeyValuePair> postParameterList = getParameterList(body);
			for (String keyword : tokenKeyWords) {
				for (KeyValuePair postParameter : postParameterList) {
					if(keyword.equals(postParameter.getName()) && StringUtils.countMatches(postParameter.getValue(),".")==2){
						found=true;
						token=postParameter.getValue();
						return true;
					}
				}
			}	
		}
		return false;
	}

	private List<KeyValuePair> getParameterList(String body) {
		int from = 0;
		int index = body.indexOf("&")==-1?body.length():body.indexOf("&");
		int parameterCount = StringUtils.countMatches(body, "&")+1;

		List<KeyValuePair> postParameterList = new ArrayList<KeyValuePair>();
		for (int i = 0; i < parameterCount; i++) {
			String parameter = body.substring(from, index);
			parameter = parameter.replace("&", "");
			
			String[] parameterSplit = parameter.split(Pattern.quote("="));
			if(parameterSplit.length>1) {
				String name = parameterSplit[0];
				String value = parameterSplit[1];
				postParameterList.add(new KeyValuePair(name, value));
				from = index;
				index = body.indexOf("&", index + 1);
				if(index == -1){
					index = body.length();
				}				
			}
		}
		return postParameterList;
	}

	@Override
	public String getToken() {
		return found ? token : "";
	}

	@Override
	public byte[] replaceToken(String newToken) {
		String body = new String(getBody());
		boolean replaced=false;
		// we cannot use the location of parameter, as the body might have changed, thus we need to search for it again
		List<KeyValuePair> postParameterList = getParameterList(body);
		for (String keyword : tokenKeyWords) {
			for (KeyValuePair postParameter : postParameterList) {
				if(keyword.equals(postParameter.getName())){
					String toReplace = postParameter.getNameAsParam()+postParameter.getValue();
					body = body.replace(toReplace, postParameter.getNameAsParam()+newToken);
					replaced = true;
				}
			}
		}
		if(!replaced){
			ConsoleOut.output("Could not replace token in post body.");
		}
		return getHelpers().buildHttpMessage(getHeaders(), body.getBytes());
	}

}

package app.tokenposition;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;

import org.apache.commons.lang.StringUtils;

import app.helpers.ConsoleOut;
import app.helpers.PostParameter;

public class PostBody extends ITokenPosition {
	private String token;
	private boolean found = false;
	private String foundKeyword;
	private List<String> tokenKeyWords = Arrays
			.asList("id_token", "ID_TOKEN", "access_token", "token");

	@Override
	public boolean positionFound() {
		if(isRequest){
			String body = new String(getBody());
			List<PostParameter> postParameterList = getParameterList(body);
			for (String keyword : tokenKeyWords) {
				for (PostParameter postParameter : postParameterList) {
					if(keyword.equals(postParameter.getName())){
						found=true;
						token=postParameter.getValue();
						foundKeyword=postParameter.getNameAsParam();
						return true;
					}
				}
			}	
		}
		return false;
	}

	private List<PostParameter> getParameterList(String body) {
		int from = 0;
		int index = body.indexOf("&")==-1?body.length():body.indexOf("&");
		int parameterCount = StringUtils.countMatches(body, "&")+1;

		List<PostParameter> postParameterList = new ArrayList<PostParameter>();
		for (int i = 0; i < parameterCount; i++) {
			String parameter = body.substring(from, index);
			parameter = parameter.replace("&", "");
			String name = parameter.split(Pattern.quote("="))[0];
			String value = parameter.split(Pattern.quote("="))[1];
			postParameterList.add(new PostParameter(name, value,from, index));
			from = index;
			index = body.indexOf("&", index + 1);
			if(index == -1){
				index = body.length();
			}
		}
		return postParameterList;
	}

	@Override
	public String getToken() {
		return !found ? "" : token;
	}

	@Override
	public byte[] replaceToken(String newToken) {
		String body = new String(getBody());
		boolean replaced=false;
		// we cannot use the location of parameter, as the body might have changed, thus we need to search for it again
		List<PostParameter> postParameterList = getParameterList(body);
		for (String keyword : tokenKeyWords) {
			for (PostParameter postParameter : postParameterList) {
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

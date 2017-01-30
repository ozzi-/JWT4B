package app.tokenposition;

import java.util.Arrays;
import java.util.List;

import burp.IExtensionHelpers;
import burp.IRequestInfo;
import burp.IResponseInfo;

public abstract class ITokenPosition {
	protected IExtensionHelpers helpers;
	protected byte[] message;
	protected boolean isRequest;
	
	public void setMessage(byte [] message, boolean isRequest) { 
		this.message = message;
		this.isRequest = isRequest;
	}
	
	public abstract boolean positionFound();
	
	public abstract String getToken();
	
	public abstract byte[] replaceToken(String newToken);

	public void setHelpers(IExtensionHelpers helpers) { 
		this.helpers = helpers;
	}
	
	protected List<String> getHeaders() { 
		if (isRequest) {
			IRequestInfo requestInfo = helpers.analyzeRequest(message);
			return requestInfo.getHeaders();
		} else {
			IResponseInfo responseInfo = helpers.analyzeResponse(message);
			return responseInfo.getHeaders();
		}
	}
	
	protected int getBodyOffset(){
		if (isRequest) {
			IRequestInfo requestInfo = helpers.analyzeRequest(message);
			return requestInfo.getBodyOffset();
		} else {
			IResponseInfo responseInfo = helpers.analyzeResponse(message);
			return responseInfo.getBodyOffset();
		}
	}
	
	protected byte[] getBody() { 
		return Arrays.copyOfRange(message, getBodyOffset(), message.length);
	}
	
	protected IExtensionHelpers getHelpers() { 
		return helpers;
	}
}

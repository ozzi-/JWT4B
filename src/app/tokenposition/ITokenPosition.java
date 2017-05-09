package app.tokenposition;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import app.helpers.ConsoleOut;
import burp.IExtensionHelpers;
import burp.IRequestInfo;
import burp.IResponseInfo;

public abstract class ITokenPosition {
	protected IExtensionHelpers helpers;
	protected byte[] message;
	protected boolean isRequest;
	public abstract boolean positionFound();
	public abstract String getToken();
	public abstract byte[] replaceToken(String newToken);
	
	public void setMessage(byte [] message, boolean isRequest) { 
		this.message = message;
		this.isRequest = isRequest;
	}
	
	public void setHelpers(IExtensionHelpers helpers) { 
		this.helpers = helpers;
	}
	
	protected List<String> getHeaders() { 
		if(message==null){
			return new ArrayList<String>();
		}
		if (isRequest) {
			IRequestInfo requestInfo = helpers.analyzeRequest(message);
			return requestInfo.getHeaders();
		} else {
			IResponseInfo responseInfo = helpers.analyzeResponse(message);
			return responseInfo.getHeaders();
		}
	}
	
	public static ITokenPosition findTokenPositionImplementation(byte[] content, boolean isRequest, IExtensionHelpers helpers) {
		List<Class<? extends ITokenPosition>> implementations = Arrays.asList(AuthorizationBearerHeader.class);

		for (Class<? extends ITokenPosition> implClass : implementations) {
			try {
				ITokenPosition impl = (ITokenPosition) implClass.getConstructors()[0].newInstance();
				impl.setHelpers(helpers);
				impl.setMessage(content, isRequest);
				if (impl.positionFound()) {
					return impl;
				}
			} catch (Exception e) {
				ConsoleOut.output(e.getMessage());
				return null;
			}
		}
		return null;
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

	public void addHeader(String header) {
		List<String> headers;
		int offset;
		if (isRequest) {
			IRequestInfo requestInfo = helpers.analyzeRequest(message);
			headers = requestInfo.getHeaders();
			offset = requestInfo.getBodyOffset();
		} else {
			IResponseInfo responseInfo = helpers.analyzeResponse(message);
			headers = responseInfo.getHeaders();
			offset = responseInfo.getBodyOffset();
		}
		headers.add(header);
		this.message = helpers.buildHttpMessage(headers, Arrays.copyOfRange(message, offset, message.length));
	}
}

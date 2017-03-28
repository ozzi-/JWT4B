package app.tokenposition;

import java.lang.reflect.InvocationTargetException;
import java.util.Arrays;
import java.util.List;

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
			} catch (InstantiationException | IllegalAccessException | IllegalArgumentException
					| InvocationTargetException | SecurityException e) {
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
}

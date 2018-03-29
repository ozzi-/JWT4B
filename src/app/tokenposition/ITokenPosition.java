package app.tokenposition;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import app.helpers.ConsoleOut;
import app.helpers.CookieFlagWrapper;
import app.helpers.Strings;
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

	private static CookieFlagWrapper cFW;

	public void setMessage(byte[] message, boolean isRequest) {
		this.message = message;
		this.isRequest = isRequest;
	}

	public void setHelpers(IExtensionHelpers helpers) {
		this.helpers = helpers;
	}

	protected List<String> getHeaders() {
		if (message == null) {
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
		List<Class<? extends ITokenPosition>> implementations = Arrays.asList(AuthorizationBearerHeader.class, PostBody.class, Cookie.class,Body.class);
		for (Class<? extends ITokenPosition> implClass : implementations) {
			try {
				List<String> headers;
				int bodyOffset;
				if (isRequest) {
					IRequestInfo requestInfo = helpers.analyzeRequest(content);
					headers = requestInfo.getHeaders();
					bodyOffset = requestInfo.getBodyOffset();
				} else {
					IResponseInfo responseInfo = helpers.analyzeResponse(content);
					headers = responseInfo.getHeaders();
					bodyOffset = responseInfo.getBodyOffset();

				}
				String body = new String(Arrays.copyOfRange(content, bodyOffset, content.length));
				ITokenPosition impl = (ITokenPosition) implClass.getConstructors()[0].newInstance(headers, body);

				impl.setHelpers(helpers);
				impl.setMessage(content, isRequest);
				if (impl.positionFound()) {
					if (impl instanceof Cookie) {
						cFW = ((Cookie) impl).getcFW();
					}else{
						cFW = new CookieFlagWrapper(false,false,false);
					}
					return impl;
				}
			} catch (Exception e) {
				// sometimes is enabled is called in order to build the views
				// before an actual request / response passes through
				if (!e.getMessage().equals("Request cannot be null") && !e.getMessage().equals("1")) {
					ConsoleOut.output(e.getMessage());
				}
				return null;
			}
		}
		return null;
	}

	protected int getBodyOffset() {
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

	public void addHeader(String headerToAdd) {
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
		headers.add(headerToAdd);
		this.message = helpers.buildHttpMessage(headers, Arrays.copyOfRange(message, offset, message.length));
	}

	public void cleanJWTHeaders() {
		List<String> headers;
		List<String> toOverwriteHeaders = new ArrayList<String>();
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

		for (String header : headers) {
			if (header.startsWith(Strings.JWTHeaderPrefix)) {
				toOverwriteHeaders.add(header);
			}
		}
		headers.removeAll(toOverwriteHeaders);
		this.message = helpers.buildHttpMessage(headers, Arrays.copyOfRange(message, offset, message.length));
	}

	public CookieFlagWrapper getcFW() {
		return cFW;
	}
}

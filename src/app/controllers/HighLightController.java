package app.controllers;

import app.tokenposition.ITokenPosition;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpListener;
import burp.IHttpRequestResponse;

public class HighLightController implements IHttpListener {
    private final IExtensionHelpers helpers;

    private static final String highlightColor = "blue";

    public HighLightController(IBurpExtenderCallbacks callbacks) {
        this.helpers = callbacks.getHelpers();
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean isRequest, IHttpRequestResponse httpRequestResponse) {
    	byte[] content;
    	if(isRequest){
    		content = httpRequestResponse.getRequest();
        }else{
        	content = httpRequestResponse.getResponse();
        }
        if(ITokenPosition.findTokenPositionImplementation(content, isRequest, helpers)!= null){
        	markRequestResponse(httpRequestResponse,"Contains a JWT");        	
        }
    }
    
    private void markRequestResponse(IHttpRequestResponse httpRequestResponse, String comment) {
        httpRequestResponse.setHighlight(highlightColor);
        httpRequestResponse.setComment(comment);
    }
}

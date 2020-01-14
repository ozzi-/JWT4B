package app.controllers;

import app.helpers.Config;
import app.tokenposition.ITokenPosition;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpListener;
import burp.IHttpRequestResponse;

public class HighLightController implements IHttpListener {
    private final IExtensionHelpers helpers;


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
        	if(!Config.interceptComment.equals("")) {
        		markRequestResponseWithComment(httpRequestResponse,Config.interceptComment);        		
        	}
            
            if(!isRequest){
                markRequestResponseWithColor(httpRequestResponse);
            }
        }
    }
    
    private void markRequestResponseWithComment(IHttpRequestResponse httpRequestResponse, String comment) {
        httpRequestResponse.setComment(comment);
    }

    private void markRequestResponseWithColor(IHttpRequestResponse httpRequestResponse) {
        httpRequestResponse.setHighlight(Config.highlightColor);
    }
}

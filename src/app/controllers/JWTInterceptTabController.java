package app.controllers;

import java.awt.Component;

import app.helpers.CustomJWTToken;
import app.helpers.Settings;
import app.tokenposition.ITokenPosition;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IMessageEditorTab;
import gui.JWTInterceptTab;
import model.JWTInterceptModel;
import model.JWTTabModel;

public class JWTInterceptTabController implements IMessageEditorTab {

	private JWTInterceptModel jwtIM;
	private JWTInterceptTab jwtST;
	private IExtensionHelpers helpers;
	private byte[] content;
	private byte[] message;
	private ITokenPosition tokenPosition;

	public JWTInterceptTabController(IBurpExtenderCallbacks callbacks,JWTInterceptModel jwIM, JWTInterceptTab jwtST) {
		this.jwtIM = jwIM;
		this.jwtST = jwtST;
		this.helpers = callbacks.getHelpers();
	}

	@Override
	public String getTabCaption() {
		return Settings.tabname;
	}

	@Override
	public Component getUiComponent() {
		return jwtST;
	}

	@Override
	public boolean isEnabled(byte[] content, boolean isRequest) {
		this.content = content;
		return ITokenPosition.findTokenPositionImplementation(content, isRequest,helpers) != null;
	}

	@Override
	public void setMessage(byte[] content, boolean isRequest) {
		this.message = content;

		tokenPosition = ITokenPosition.findTokenPositionImplementation(content, isRequest,helpers);
		jwtIM.setJWT(tokenPosition.getToken());
	
		CustomJWTToken a = new CustomJWTToken(jwtIM.getJWT());
		jwtIM.setJWTJSON(ReadableTokenFormat.getReadableFormat(a));
		
		jwtST.updateSetView();
	}

	@Override
	public byte[] getMessage() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public boolean isModified() {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public byte[] getSelectedData() {
		// TODO Auto-generated method stub
		return null;
	}

}

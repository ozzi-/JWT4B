package app.controllers;

import java.awt.Component;

import app.helpers.Settings;
import app.tokenposition.ITokenPosition;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IMessageEditorTab;
import gui.JWTInterceptTab;
import model.JWTInterceptModel;

public class JWTInterceptTabController implements IMessageEditorTab {

	private JWTInterceptModel jwtSTM;
	private JWTInterceptTab jwtST;
	private IExtensionHelpers helpers;
	private byte[] content;

	public JWTInterceptTabController(IBurpExtenderCallbacks callbacks,JWTInterceptModel jwtSTM, JWTInterceptTab jwtST) {
		this.jwtSTM = jwtSTM;
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
		// TODO Auto-generated method stub
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

package app.controllers;

import java.awt.Component;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;

import app.helpers.ConsoleOut;
import app.helpers.CustomJWToken;
import app.helpers.Settings;
import app.tokenposition.ITokenPosition;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IMessageEditorTab;
import burp.IRequestInfo;
import burp.IResponseInfo;
import gui.JWTInterceptTab;
import model.JWTInterceptModel;

public class JWTInterceptTabController implements IMessageEditorTab {

	private JWTInterceptModel jwtIM;
	private JWTInterceptTab jwtST;
	private IExtensionHelpers helpers;
	private byte[] content;
	private byte[] message;
	private ITokenPosition tokenPosition;
	private boolean randomKey;
	private boolean keepOriginalSignature;
	private boolean recalculateSignature;
	private boolean isRequest;

	public JWTInterceptTabController(IBurpExtenderCallbacks callbacks, JWTInterceptModel jwIM, JWTInterceptTab jwtST) {
		this.jwtIM = jwIM;
		this.jwtST = jwtST;
		this.helpers = callbacks.getHelpers();

		ActionListener randomKeyListener = new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				radioButtonChanged(true, false, false);
			}
		};
		ActionListener originalSignatureListener = new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				radioButtonChanged(false, true, false);
			}
		};
		ActionListener recalculateSignatureListener = new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				radioButtonChanged(false, false, true);
			}
		};

		jwtST.registerActionListeners(randomKeyListener, originalSignatureListener, recalculateSignatureListener);
	}

	private void radioButtonChanged(boolean cRK, boolean cOS, boolean cRS) {
		randomKey = jwtST.getRdbtnRandomKey().isSelected();
		keepOriginalSignature = jwtST.getRdbtnOriginalSignature().isSelected();
		recalculateSignature = jwtST.getRdbtnRecalculateSignature().isSelected();
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
		return ITokenPosition.findTokenPositionImplementation(content, isRequest, helpers) != null;
	}

	@Override
	public void setMessage(byte[] content, boolean isRequest) {
		this.message = content;
		this.isRequest = isRequest;

		tokenPosition = ITokenPosition.findTokenPositionImplementation(content, isRequest, helpers);
		jwtIM.setJWT(tokenPosition.getToken());

		CustomJWToken cJWT = new CustomJWToken(jwtIM.getJWT());
		jwtIM.setJWTJSON(ReadableTokenFormat.getReadableFormat(cJWT));
		jwtIM.setSignature(cJWT.getSignature());

		jwtST.updateSetView();
	}

	@Override
	public byte[] getMessage() {
		
		if  (recalculateSignature) {
			// TODO recalculate the signature if jwt was changed
		} else if (randomKey) {
			// TODO Vetsch ;)
		} else if (keepOriginalSignature){
			jwtIM.setSignature(jwtIM.getOriginalSignature());
		}
		
		String newMessage = new String(this.message);
		//a = newMessage.split("\\r?\\n"));
		
		ConsoleOut.output(newMessage);
		
		
		return null;
	}

	@Override
	public boolean isModified() {
		// TODO set true when model changed
		return false;
	}

	@Override
	public byte[] getSelectedData() {
		return jwtST.getSelectedData().getBytes();
	}

}

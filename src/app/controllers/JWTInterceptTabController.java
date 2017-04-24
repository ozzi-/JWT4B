package app.controllers;

import java.awt.Component;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.UnsupportedEncodingException;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;

import com.auth0.jwt.algorithms.Algorithm;

import app.algorithm.AlgorithmLinker;
import app.controllers.ReadableTokenFormat.InvalidTokenFormat;
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
		
		CustomJWToken token = null;
		try {
			token = ReadableTokenFormat.getTokenFromReadableFormat(jwtST.getJWTfromArea());

		} catch (InvalidTokenFormat e) {
			// TODO give user feedback, that he broke the token
			ConsoleOut.output(e.getMessage());
			return null; // returning null is interpreted same as sending original message
		}
		
		if  (recalculateSignature) {
			Algorithm algo;
			try {
				ConsoleOut.output("Recalculating Signature with Secret - "+jwtIM.getJWTKey());
				algo = AlgorithmLinker.getAlgorithm(token.getAlgorithm(),jwtIM.getJWTKey());
				token.calculateAndSetSignature(algo);
			} catch (IllegalArgumentException | UnsupportedEncodingException e) {
				ConsoleOut.output(e.getStackTrace().toString());
			}
		} else if (randomKey) {
			ConsoleOut.output("Generating Random Key for Signature Calculation");
			String randomKey = AlgorithmLinker.getRandomKey(token.getAlgorithm());
			jwtIM.setJWTKey(randomKey);
		} else if (keepOriginalSignature){
			jwtIM.setSignature(jwtIM.getOriginalSignature());
		}
		
		this.message = this.tokenPosition.replaceToken(token.getToken());
		return this.message;
			
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

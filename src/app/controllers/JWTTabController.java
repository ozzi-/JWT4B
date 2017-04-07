package app.controllers;

import java.awt.Component;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;

import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;

import app.algorithm.AlgorithmLinker;
import app.helpers.ConsoleOut;
import app.helpers.CustomJWToken;
import app.helpers.Settings;
import app.helpers.Strings;
import app.tokenposition.ITokenPosition;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IMessageEditorTab;
import gui.JWTViewTab;
import model.JWTTabModel;

// TODO verificationResult differing default grey. Result Label improvements.
public class JWTTabController implements IMessageEditorTab {

	private IExtensionHelpers helpers;
	private byte[] message;
	private ITokenPosition tokenPosition;
	private String state = Strings.tokenStateOriginal;
	private ArrayList<JWTTabModel> modelStateList = new ArrayList<JWTTabModel>();
	private byte[] content;
	private JWTTabModel jwtTM;
	private JWTViewTab jwtVT;

	public JWTTabController(IBurpExtenderCallbacks callbacks, JWTTabModel jwtTM, JWTViewTab jwtVT) {
		this.helpers = callbacks.getHelpers();
		this.jwtTM = jwtTM;
		this.jwtVT  = jwtVT;
		
		DocumentListener documentListener = new DocumentListener() {
			
			@Override
			public void removeUpdate(DocumentEvent arg0) {
				jwtTM.setKey(jwtVT.getKeyValue());
				checkKey(jwtTM.getKey());
			}

			@Override
			public void insertUpdate(DocumentEvent arg0) {
				jwtTM.setKey(jwtVT.getKeyValue());
				checkKey(jwtTM.getKey());				
			}
			
			@Override
			public void changedUpdate(DocumentEvent arg0) {
				jwtTM.setKey(jwtVT.getKeyValue());
				checkKey(jwtTM.getKey());
			}
		};
		
		jwtVT.registerDocumentListener(documentListener);
	}
	
	@Override
	public String getTabCaption() {
		return Settings.tabname;
	}

	@Override
	public Component getUiComponent() {
		return this.jwtVT;
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
		jwtTM.setJWT(tokenPosition.getToken());
	
		CustomJWToken a = new CustomJWToken(jwtTM.getJWT());
		jwtTM.setJWTJSON(ReadableTokenFormat.getReadableFormat(a));
		
		JWTTabModel current = new JWTTabModel(jwtTM.getKey(), content);
		int containsIndex = modelStateList.indexOf(current);

		// we know this request, load the last
		if (containsIndex != -1) {
			jwtTM.setKey(modelStateList.get(containsIndex).getKey());
			jwtTM.setVerificationLabel(modelStateList.get(containsIndex).getVerificationLabel());
			jwtTM.setVerificationColor(modelStateList.get(containsIndex).getVerificationColor());
			// we haven't seen this request yet, add it and set the view to
			// default
		} else {
			modelStateList.add(current);
			//typedTab.setKeyValue("");
			jwtTM.setVerificationColor(Settings.colorUndefined);
			jwtTM.setVerificationResult("");
		}
		jwtVT.updateSetView();
	}

	@Override
	public byte[] getMessage() {
		return message;
	}

	@Override
	public boolean isModified() {
		return false;
	}

	public void checkKey(String key) {
		String curAlgo = getCurrentAlgorithm();
		try {
			JWTVerifier verifier = JWT.require(AlgorithmLinker.getAlgorithm(curAlgo, key)).build();
			DecodedJWT test = verifier.verify(jwtTM.getJWT());
			jwtTM.setVerificationLabel(Strings.verificationValid);
			jwtTM.setVerificationColor(Settings.colorValid);
			test.getAlgorithm();
			jwtVT.updateSetView();
		} catch (JWTVerificationException e) {
			ConsoleOut.output("Verification failed (" + e.getMessage() + ")");
			jwtTM.setVerificationLabel(Strings.verificationWrongKey);
			jwtTM.setVerificationColor(Settings.colorInvalid);
			jwtVT.updateSetView();
		} catch (IllegalArgumentException | UnsupportedEncodingException e) {
			ConsoleOut.output("Verification failed (" + e.getMessage() + ")");
			jwtTM.setVerificationLabel(Strings.verificationInvalidKey);
			jwtTM.setVerificationColor(Settings.colorProblemInvalid);
			jwtVT.updateSetView();
		}
		JWTTabModel current = new JWTTabModel(key, content);
		int containsIndex = modelStateList.indexOf(current);
		if (containsIndex != -1) { // we know this request, update the viewstate
			modelStateList.get(containsIndex).setKeyValueAndHash(key, current.getHashCode());
			modelStateList.get(containsIndex).setVerificationResult(jwtTM.getVerificationLabel());
			modelStateList.get(containsIndex).setVerificationColor(jwtTM.getVerificationColor());
		}
	}

	@Override
	public byte[] getSelectedData() {
		return jwtVT.getSelectedData().getBytes();
	}


	public String getCurrentAlgorithm() {
		return new CustomJWToken(jwtTM.getJWT()).getAlgorithm();
	}


	public String getState() {
		return state;
	}

}

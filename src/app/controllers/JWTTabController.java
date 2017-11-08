package app.controllers;

import java.awt.Component;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.List;

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
import model.TimeClaim;

public class JWTTabController implements IMessageEditorTab {

	private IExtensionHelpers helpers;
	private byte[] message;
	private ITokenPosition tokenPosition;
	private String state = Strings.tokenStateOriginal;
	private ArrayList<JWTTabModel> modelStateList = new ArrayList<JWTTabModel>();
	private byte[] content;
	private JWTTabModel jwtTM;
	private JWTViewTab jwtVT;

	public JWTTabController(IBurpExtenderCallbacks callbacks, final JWTTabModel jwtTM, final JWTViewTab jwtVT) {
		this.helpers = callbacks.getHelpers();
		this.jwtTM = jwtTM;
		this.jwtVT = jwtVT;

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
	public boolean isEnabled(byte[] content, boolean isRequest) {
		this.content = content;
		return ITokenPosition.findTokenPositionImplementation(content, isRequest, helpers) != null;
	}

	@Override
	public void setMessage(byte[] content, boolean isRequest) {
		this.message = content;

		tokenPosition = ITokenPosition.findTokenPositionImplementation(content, isRequest, helpers);
		jwtTM.setJWT(tokenPosition.getToken());
		CustomJWToken jwt = new CustomJWToken(jwtTM.getJWT());
		jwtTM.setJWTJSON(ReadableTokenFormat.getReadableFormat(jwt));
		List<TimeClaim> tcl = jwt.getTimeClaimList();
		jwtTM.setTimeClaims(tcl);
		jwtTM.setcFW(tokenPosition.getcFW());

		JWTTabModel current = new JWTTabModel(jwtTM.getKey(), content);
		int containsIndex = modelStateList.indexOf(current);

		// we know this request, load it
		if (containsIndex != -1) {
			JWTTabModel knownModel = modelStateList.get(containsIndex);
			jwtTM.setKey(knownModel.getKey());
			jwtTM.setVerificationColor(knownModel.getVerificationColor());
			jwtTM.setVerificationLabel(knownModel.getVerificationLabel());
			// we haven't seen this request yet, add it and set the view to
			// default
		} else {
			modelStateList.add(current);
			jwtTM.setVerificationColor(Settings.colorUndefined);
			jwtTM.setVerificationResult("");
			jwtTM.setKey("");
		}
		String algoType = AlgorithmLinker.getTypeOf(getCurrentAlgorithm());
		jwtVT.updateSetView(algoType);
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
		jwtTM.setVerificationResult("");
		String curAlgo = getCurrentAlgorithm();
		String algoType = AlgorithmLinker.getTypeOf(getCurrentAlgorithm());
		try {
			JWTVerifier verifier = JWT.require(AlgorithmLinker.getVerifierAlgorithm(curAlgo, key)).build();
			DecodedJWT test = verifier.verify(jwtTM.getJWT());
			jwtTM.setVerificationLabel(Strings.verificationValid);
			jwtTM.setVerificationColor(Settings.colorValid);
			test.getAlgorithm();
			jwtVT.updateSetView(algoType);
		} catch (JWTVerificationException e) {
			ConsoleOut.output("Verification failed (" + e.getMessage() + ")");
			jwtTM.setVerificationLabel(Strings.verificationWrongKey);
			jwtTM.setVerificationColor(Settings.colorInvalid);
			jwtTM.setVerificationResult(e.getMessage());
			jwtVT.updateSetView(algoType);
		} catch (IllegalArgumentException | UnsupportedEncodingException e) {
			ConsoleOut.output("Verification failed (" + e.getMessage() + ")");
			jwtTM.setVerificationResult(e.getMessage());
			jwtTM.setVerificationLabel(Strings.verificationInvalidKey);
			jwtTM.setVerificationColor(Settings.colorProblemInvalid);
			jwtVT.updateSetView(algoType);
		}
		JWTTabModel current = new JWTTabModel(key, content);
		int containsIndex = modelStateList.indexOf(current);
		if (containsIndex != -1) { // we know this request, update the viewstate
			JWTTabModel knownState = modelStateList.get(containsIndex);
			knownState.setKeyValueAndHash(key, current.getHashCode());
			knownState.setVerificationResult(jwtTM.getVerificationLabel());
			knownState.setVerificationColor(jwtTM.getVerificationColor());
		}
	}

	@Override
	public byte[] getSelectedData() {
		return jwtVT.getSelectedData().getBytes();
	}

	@Override
	public String getTabCaption() {
		return Settings.tabname;
	}

	@Override
	public Component getUiComponent() {
		return this.jwtVT;
	}

	public String getCurrentAlgorithm() {
		return new CustomJWToken(jwtTM.getJWT()).getAlgorithm();
	}

	public String getState() {
		return state;
	}

}

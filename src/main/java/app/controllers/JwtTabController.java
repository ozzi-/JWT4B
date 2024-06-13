package app.controllers;

import java.awt.Component;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpMessage;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpResponseEditor;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.exceptions.InvalidClaimException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;

import app.algorithm.AlgorithmType;
import app.algorithm.AlgorithmWrapper;
import app.helpers.Output;
import app.tokenposition.ITokenPosition;
import gui.JWTViewTab;
import model.CustomJWToken;
import model.JWTTabModel;
import model.Settings;
import model.Strings;
import model.TimeClaim;

// view to check JWTs such as in the HTTP history
public class JwtTabController implements ExtensionProvidedHttpRequestEditor, ExtensionProvidedHttpResponseEditor {

	private ITokenPosition tokenPosition;
	private final ArrayList<JWTTabModel> modelStateList = new ArrayList<JWTTabModel>();
	private byte[] content;
	private final JWTTabModel jwtTM;
	private final JWTViewTab jwtVT;
	boolean isRequest;
	private HttpRequestResponse httpRequestResponse;

	public JwtTabController(final JWTTabModel jwtTM, final JWTViewTab jwtVT, boolean isRequest) {
		this.jwtTM = jwtTM;
		this.jwtVT = jwtVT;
		this.isRequest = isRequest;

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
	public HttpRequest getRequest() {
		return httpRequestResponse.request();
	}

	@Override
	public HttpResponse getResponse() {
		return httpRequestResponse.response();
	}

	@Override
	public void setRequestResponse(HttpRequestResponse requestResponse) {
		httpRequestResponse = requestResponse;
		HttpMessage httpMessage;

		if (isRequest) {
			httpMessage = requestResponse.request();
		} else {
			httpMessage = requestResponse.response();
		}

		try {
			tokenPosition = ITokenPosition.findTokenPositionImplementation(httpMessage, this.isRequest);
			jwtTM.setJWT(Objects.requireNonNull(tokenPosition).getToken());
		} catch (Exception e) {
			Output.outputError("Exception setting message: " + e.getMessage());
		}
		CustomJWToken jwt = new CustomJWToken(jwtTM.getJWT());
		jwtTM.setJWTJSON(ReadableTokenFormat.getReadableFormat(jwt));
		List<TimeClaim> tcl = jwt.getTimeClaimList();
		jwtTM.setTimeClaims(tcl);
		if (tokenPosition != null) {
			jwtTM.setcFW(tokenPosition.getcFW());
		}

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
			jwtTM.setVerificationColor(Settings.COLOR_UNDEFINED);
			jwtTM.setVerificationResult("");
			jwtTM.setKey("");
		}
		AlgorithmType algoType = AlgorithmWrapper.getTypeOf(getCurrentAlgorithm());
		jwtVT.updateSetView(algoType);
	}

	@Override
	public boolean isEnabledFor(HttpRequestResponse requestResponse) {
		HttpMessage message;

		if (this.isRequest) {
			this.content = requestResponse.request().toString().getBytes();
			message = requestResponse.request();
		} else {
			this.content = requestResponse.response().toString().getBytes();
			message = requestResponse.response();
		}

		return ITokenPosition.findTokenPositionImplementation(message, this.isRequest) != null;
	}

	@Override
	public String caption() {
		return Settings.TAB_NAME;
	}

	@Override
	public Component uiComponent() {
		return this.jwtVT;
	}

	@Override
	public Selection selectedData() {
		return Selection.selection(ByteArray.byteArray(jwtVT.getSelectedData().getBytes()));
	}

	@Override
	public boolean isModified() {
		return false;
	}

	public void checkKey(String key) {
		jwtTM.setVerificationResult("");
		String curAlgo = getCurrentAlgorithm();
		AlgorithmType algoType = AlgorithmWrapper.getTypeOf(getCurrentAlgorithm());
		try {
			JWTVerifier verifier = JWT.require(AlgorithmWrapper.getVerifierAlgorithm(curAlgo, key)).build();
			DecodedJWT test = verifier.verify(jwtTM.getJWT());
			jwtTM.setVerificationLabel(Strings.VALID_VERFICIATION);
			jwtTM.setVerificationColor(Settings.getValidColor());
			test.getAlgorithm();
			jwtVT.updateSetView(algoType);
		} catch (JWTVerificationException e) {
			if (e instanceof SignatureVerificationException) {
				jwtTM.setVerificationColor(Settings.getInvalidColor());
				jwtTM.setVerificationLabel(Strings.INVALID_SIGNATURE_VERIFICATION);
			} else if (e instanceof InvalidClaimException) {
				jwtTM.setVerificationColor(Settings.getProblemColor());
				jwtTM.setVerificationLabel(Strings.INVALID_CLAIM_VERIFICATION);
			} else {
				jwtTM.setVerificationColor(Settings.getProblemColor());
				jwtTM.setVerificationLabel(Strings.GENERIC_ERROR_VERIFICATION);
			}
			jwtTM.setVerificationResult(e.getMessage());
			jwtVT.updateSetView(algoType);
		} catch (IllegalArgumentException e) {
			jwtTM.setVerificationResult(e.getMessage());
			jwtTM.setVerificationLabel(Strings.INVALID_KEY_VERIFICATION);
			jwtTM.setVerificationColor(Settings.getProblemColor());
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

	public String getCurrentAlgorithm() {
		return new CustomJWToken(jwtTM.getJWT()).getAlgorithm();
	}

}

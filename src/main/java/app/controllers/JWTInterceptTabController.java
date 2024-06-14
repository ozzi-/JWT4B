package app.controllers;

import java.awt.Component;
import java.awt.FileDialog;
import java.awt.Frame;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.awt.event.KeyListener;
import java.nio.charset.StandardCharsets;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.List;
import java.util.Objects;

import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.SwingUtilities;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

import app.helpers.*;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpMessage;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpResponseEditor;
import org.apache.commons.codec.binary.Hex;

import com.auth0.jwt.algorithms.Algorithm;
import com.eclipsesource.json.Json;
import com.eclipsesource.json.JsonObject;

import app.algorithm.AlgorithmWrapper;
import app.tokenposition.ITokenPosition;
import gui.JWTInterceptTab;
import model.CustomJWToken;
import model.JWTInterceptModel;
import model.Settings;
import model.Strings;
import model.TimeClaim;

// used in the proxy intercept and repeater tabs
public class JWTInterceptTabController implements ExtensionProvidedHttpRequestEditor, ExtensionProvidedHttpResponseEditor {

	private final JWTInterceptModel jwtIM;
	private final JWTInterceptTab jwtST;
	private ITokenPosition tokenPosition;
	private boolean resignOnType;
	private boolean randomKey;
	private boolean chooseSignature;
	private boolean recalculateSignature;
	private String algAttackMode;
	private boolean cveAttackMode;
	private boolean edited;
	private String originalSignature;
	private boolean addMetaHeader;
	private static final String HEX_MARKER = "0x";
	private final boolean isRequest;
	private HttpRequestResponse httpRequestResponse;

	public JWTInterceptTabController(JWTInterceptModel jwIM, JWTInterceptTab jwtST, boolean isRequest) {
		this.jwtIM = jwIM;
		this.jwtST = jwtST;
		this.isRequest = isRequest;
		createAndRegisterActionListeners(jwtST);
	}

	private void cveAttackChanged() {
		edited = true;
		JCheckBox jcb = jwtST.getCVEAttackCheckBox();
		cveAttackMode = jcb.isSelected();
		jwtST.getNoneAttackComboBox().setEnabled(!cveAttackMode);
		jwtST.getRdbtnDontModify().setEnabled(!cveAttackMode);
		jwtST.getRdbtnOriginalSignature().setEnabled(!cveAttackMode);
		jwtST.getRdbtnRandomKey().setEnabled(!cveAttackMode);
		jwtST.getRdbtnRecalculateSignature().setEnabled(!cveAttackMode);
		jwtST.setKeyFieldState(!cveAttackMode);
		jwtST.getCVECopyBtn().setVisible(cveAttackMode);

		if (cveAttackMode) {
			jwtST.getRdbtnDontModify().setSelected(true);
			jwtST.getRdbtnOriginalSignature().setSelected(false);
			jwtST.getRdbtnRandomKey().setSelected(false);
			jwtST.getRdbtnRecalculateSignature().setSelected(false);
			CustomJWToken token = jwtIM.getJwToken();
			String headerJSON = token.getHeaderJson();
			JsonObject headerJSONObj = Json.parse(headerJSON).asObject();
			headerJSONObj.set("alg", "RS256");
			JsonObject jwk = new JsonObject();
			jwk.add("kty", "RSA");
			jwk.add("kid", "jwt4b@portswigger.net");
			jwk.add("use", "sig");
			RSAPublicKey pk = KeyHelper.loadCVEAttackPublicKey();
			jwk.add("n", Base64.getUrlEncoder().encodeToString(pk.getPublicExponent().toByteArray()));
			jwk.add("e", Base64.getUrlEncoder().encodeToString(pk.getModulus().toByteArray()));
			headerJSONObj.add("jwk", jwk);
			token.setHeaderJson(headerJSONObj.toString());
			try {
				Algorithm algo = AlgorithmWrapper.getSignerAlgorithm(token.getAlgorithm(), Config.cveAttackModePrivateKey);
				token.calculateAndSetSignature(algo);
				reflectChangeToView(token, true);
			} catch (Exception e) {
				reportError("Failed to sign when using cve attack mode - " + e.getMessage());
			}
		} else {
			jwtST.setKeyFieldValue("");
			jwtST.setKeyFieldState(false);
			CustomJWToken customJWToken = new CustomJWToken(jwtIM.getOriginalJWT());
			jwtIM.setJwToken(customJWToken);
			jwtST.getNoneAttackComboBox().setSelectedIndex(0);
			reflectChangeToView(jwtIM.getJwToken(), true);
		}
	}

	private void signKeyChange() {
		jwtIM.setJWTSignatureKey(jwtST.getKeyFieldValue());
		try {
			if (jwtIM.getJWTKey() != null && jwtIM.getJWTKey().length() > 0 && jwtST.getKeyField().isEnabled()) {
				String key = getKeyWithHexDetection(jwtIM);
				Output.output("Signing with manually entered key '" + key + "' (" + jwtIM.getJWTKey() + ")");
				CustomJWToken token = ReadableTokenFormat.getTokenFromView(jwtST);

				if (Config.o365Support && O365.isO365Request(token, token.getAlgorithm())) {
					O365.handleO365(key, token);
					reflectChangeToView(token, false);
				} else {
					Algorithm algo = AlgorithmWrapper.getSignerAlgorithm(token.getAlgorithm(), key);
					token.calculateAndSetSignature(algo);
					reflectChangeToView(token, false);
				}
				clearError();
			}
		} catch (Exception e) {
			int len = 8;
			String key = jwtST.getKeyFieldValue();
			key = key.length() > len ? key.substring(0, len) + "..." : key;
			reportError("Cannot sign with key " + key + " - " + e.getMessage());
		}
	}

	private String getKeyWithHexDetection(JWTInterceptModel jwtIM) {
		String key = jwtIM.getJWTKey();
		if (key.startsWith(HEX_MARKER)) {
			try {
				key = key.substring(2);
				byte[] bytes = Hex.decodeHex(key);
				key = new String(bytes, StandardCharsets.ISO_8859_1);
			} catch (Exception e) {
				key = jwtIM.getJWTKey();
			}
		}
		return key;
	}

	private void algAttackChanged() {
		edited = true;
		JComboBox<String> jCB = jwtST.getNoneAttackComboBox();
		switch (jCB.getSelectedIndex()) {
		default:
		case 0:
			algAttackMode = null;
			break;
		case 1:
			algAttackMode = "none";
			break;
		case 2:
			algAttackMode = "None";
			break;
		case 3:
			algAttackMode = "nOnE";
			break;
		case 4:
			algAttackMode = "NONE";
			break;
		}

		CustomJWToken token = jwtIM.getJwToken();
		String header = token.getHeaderJson();
		if (algAttackMode == null) {
			Output.output("Resetting alg attack mode - " + jwtIM.getOriginalJWToken().getAlgorithm());
			token.setHeaderJson(header.replace(token.getAlgorithm(), jwtIM.getOriginalJWToken().getAlgorithm()));
			token.setSignature(originalSignature);
			jwtST.getRdbtnDontModify().setSelected(true);
			radioButtonChanged(true, false, false, false, false);
			jwtST.setRadiosState(true);
			jwtST.setKeyFieldState(true);
		} else {
			jwtST.getRdbtnDontModify().setSelected(true);
			jwtST.setRadiosState(false);
			jwtST.setKeyFieldState(false);
			token.setSignature("");
			token.setHeaderJson(header.replace(token.getAlgorithm(), algAttackMode));
		}
		reflectChangeToView(token, true);
	}

	private void radioButtonChanged(boolean cDM, boolean cRK, boolean cOS, boolean cRS, boolean cCS) {
		clearError();
		resignOnType = !cDM && !cOS;
		boolean oldRandomKey = randomKey;
		edited = true;
		addMetaHeader = false;
		boolean dontModifySignature = jwtST.getRdbtnDontModify().isSelected();
		randomKey = jwtST.getRdbtnRandomKey().isSelected();
		boolean keepOriginalSignature = jwtST.getRdbtnOriginalSignature().isSelected();
		recalculateSignature = jwtST.getRdbtnRecalculateSignature().isSelected();
		chooseSignature = jwtST.getRdbtnChooseSignature().isSelected();

		jwtST.setKeyFieldState(!keepOriginalSignature && !dontModifySignature && !randomKey && !chooseSignature);
		if (keepOriginalSignature) {
			CustomJWToken origSignatureToken = jwtIM.getJwToken().setSignature(originalSignature);
			jwtIM.setJwToken(origSignatureToken);
			jwtIM.setJWTSignatureKey("");
			jwtST.setKeyFieldValue("");
			jwtST.updateSetView(false);
		} else if (dontModifySignature) {
			jwtIM.setJWTSignatureKey("");
			jwtST.setKeyFieldValue("");
		} else if (randomKey) {
			addMetaHeader = true;
			if (!oldRandomKey) {
				generateRandomKey();
			}
		} else if (cCS) {
			FileDialog dialog = new FileDialog((Frame) null, "Select File to Open");
			dialog.setMode(FileDialog.LOAD);
			dialog.setVisible(true);
			if (dialog.getFile() != null) {
				String file = dialog.getDirectory() + dialog.getFile();
				Output.output(file + " chosen.");
				String chosen = Strings.filePathToString(file);
				// TODO error will be redirected to Output.outputError, but make sure this case
				// will be shown in UI too
				jwtIM.setJWTSignatureKey(chosen);
				jwtST.setKeyFieldValue(chosen);
				jwtST.updateSetView(false);
			}
		} else if ((recalculateSignature || chooseSignature)) {
			if (recalculateSignature) {
				String cleanKey = KeyHelper.cleanKey(jwtST.getKeyFieldValue());
				jwtIM.setJWTSignatureKey(cleanKey);
			}
			Algorithm algo;
			try {
				if (jwtIM.getJWTKey().length() > 0) {
					CustomJWToken token = jwtIM.getJwToken();
					Output.output("Recalculating Signature with Secret - '" + jwtIM.getJWTKey() + "'");
					algo = AlgorithmWrapper.getSignerAlgorithm(token.getAlgorithm(), jwtIM.getJWTKey());
					token.calculateAndSetSignature(algo);
					reflectChangeToView(token, true);
					addMetaHeader = true;
				}
			} catch (IllegalArgumentException e) {
				reportError("Exception while recalculating signature - " + e.getMessage());
			}
		}
	}

	private void clearError() {
		jwtIM.setProblemDetail("");
		jwtST.setProblemLbl("");
	}

	private void reportError(String error) {
		Output.outputError(error);
		jwtIM.setProblemDetail(error);
		jwtST.setProblemLbl(jwtIM.getProblemDetail());
	}

	private void generateRandomKey() {
		SwingUtilities.invokeLater(() -> {
			try {
				CustomJWToken token = ReadableTokenFormat.getTokenFromView(jwtST);
				String generatedRandomKey = KeyHelper.getRandomKey(token.getAlgorithm());
				Output.output("Generating Random Key for Signature Calculation: " + generatedRandomKey);
				jwtIM.setJWTSignatureKey(generatedRandomKey);
				Algorithm algo = AlgorithmWrapper.getSignerAlgorithm(token.getAlgorithm(), generatedRandomKey);
				token.calculateAndSetSignature(algo);
				jwtIM.setJwToken(token);
				jwtST.setKeyFieldValue(generatedRandomKey);
				jwtST.updateSetView(false);
			} catch (Exception e) {
				reportError("Exception during random key generation & signing: " + e.getMessage());
			}
		});
	}

	private void replaceTokenInMessage() {
		CustomJWToken token;
		if (!jwtInUIisValid()) {
			Output.outputError("Wont replace JWT as invalid");
			edited = false;
			return;
		}
		try {
			token = ReadableTokenFormat.getTokenFromView(jwtST);
			Output.output("Replacing token: " + token.getToken());
			// token may be null, if it is invalid JSON, if so, don't try changing anything
			if (token.getToken() != null) {
				this.tokenPosition.replaceToken(token.getToken());
			}
		} catch (Exception e) {
			// TODO is this visible to user?
			reportError("Could not replace token in message: " + e.getMessage());
		}
	}

	private void addLogHeadersToRequest() {
		if (addMetaHeader) {
			this.tokenPosition.cleanJWTHeaders();
			this.tokenPosition.addHeader(Strings.JWT_HEADER_PREFIX, Strings.JWT_HEADER_INFO);
			this.tokenPosition.addHeader(Strings.JWT_HEADER_PREFIX, "SIGNER-KEY " + jwtIM.getJWTKey());
			if (PublicKeyBroker.publicKey != null) {
				this.tokenPosition.addHeader(Strings.JWT_HEADER_PREFIX, "SIGNER-PUBLIC-KEY " + PublicKeyBroker.publicKey);
				PublicKeyBroker.publicKey = null;
			}
		}
	}

	private void reflectChangeToView(CustomJWToken token, boolean updateKey) {
		jwtIM.setJwToken(token);
		jwtST.updateSetView(false, updateKey);
	}

	private void handleJWTAreaTyped() {
		if (jwtInUIisValid()) {
			clearError();
		} else {
			// TODO determine error more accurately, what exactly is wrong with the jwt
			reportError("invalid JWT");
			return;
		}
		if (resignOnType) {
			Output.output("Recalculating signature as key typed");
			CustomJWToken token = null;
			try {
				token = ReadableTokenFormat.getTokenFromView(jwtST);
			} catch (Exception e) {
				reportError("JWT can't be parsed - " + e.getMessage());
			}
			if (jwtIM.getJWTKey().length() == 0) {
				reportError("Can't resign with an empty key");
			}
			try {
				Algorithm algo = AlgorithmWrapper.getSignerAlgorithm(Objects.requireNonNull(token).getAlgorithm(), jwtIM.getJWTKey());
				token.calculateAndSetSignature(algo);
				jwtIM.setJwToken(token);
				jwtST.getJwtSignatureArea().setText(jwtIM.getJwToken().getSignature());
			} catch (Exception e) {
				reportError("Could not resign: " + e.getMessage());
			}
		}
	}

	public boolean jwtInUIisValid() {
		boolean valid = false;
		try {
			CustomJWToken tokenFromView = ReadableTokenFormat.getTokenFromView(jwtST);
			if (tokenFromView.getHeaderJsonNode().get("alg") != null) {
				valid = CustomJWToken.isValidJWT(tokenFromView.getToken());
			}
		} catch (Exception ignored) {
			// ignored
		}
		return valid;
	}

	protected boolean hasNotChanged() {
		// see
		// https://github.com/PortSwigger/example-custom-editor-tab/blob/master/java/BurpExtender.java#L119
		return !edited && !recalculateSignature && !randomKey && !chooseSignature && algAttackMode == null && !cveAttackMode;
	}

	protected void performUpdate() {
		clearError();
		radioButtonChanged(true, false, false, false, false);
		jwtST.getCVEAttackCheckBox().setSelected(false);
		replaceTokenInMessage();
		addLogHeadersToRequest();
	}

	@Override
	public HttpRequest getRequest() {
		if (hasNotChanged()) {
			return httpRequestResponse.request();
		}

		performUpdate();
		return this.tokenPosition.getRequest();
	}

	@Override
	public HttpResponse getResponse() {
		if (hasNotChanged()) {
			return httpRequestResponse.response();
		}

		performUpdate();
		return this.tokenPosition.getResponse();
	}

	@Override
	public void setRequestResponse(HttpRequestResponse requestResponse) {
		httpRequestResponse = requestResponse;
		HttpMessage httpMessage;

		if (isRequest) {
			httpMessage = httpRequestResponse.request();
		} else {
			httpMessage = httpRequestResponse.response();
		}

		edited = false;
		tokenPosition = ITokenPosition.findTokenPositionImplementation(httpMessage, isRequest);
		boolean messageContainsJWT = tokenPosition != null;
		if (messageContainsJWT) {
			String token = tokenPosition.getToken();
			CustomJWToken cJWT = new CustomJWToken(token);
			jwtIM.setOriginalJWToken(new CustomJWToken(token));
			jwtIM.setOriginalJWT(token);
			List<TimeClaim> tcl = cJWT.getTimeClaimList();
			jwtIM.setTimeClaims(tcl);
			jwtIM.setJwToken(cJWT);
			originalSignature = cJWT.getSignature();
			jwtIM.setcFW(tokenPosition.getcFW());
			jwtST.updateSetView(Config.resetEditor);
			algAttackMode = null;
			if (Config.resetEditor) {
				jwtST.getNoneAttackComboBox().setSelectedIndex(0);
			}
		} else {
			jwtST.updateSetView(true);
		}
	}

	@Override
	public boolean isEnabledFor(HttpRequestResponse requestResponse) {
		HttpMessage httpMessage;

		if (this.isRequest) {
			httpMessage = requestResponse.request();
		} else {
			httpMessage = requestResponse.response();
		}

		return ITokenPosition.findTokenPositionImplementation(httpMessage, this.isRequest) != null;
	}

	@Override
	public String caption() {
		return Settings.TAB_NAME;
	}

	@Override
	public Component uiComponent() {
		return jwtST;
	}

	@Override
	public Selection selectedData() {
		return Selection.selection(ByteArray.byteArray(jwtST.getSelectedData().getBytes()));
	}

	@Override
	public boolean isModified() {
		return edited;
	}

	private void createAndRegisterActionListeners(JWTInterceptTab jwtST) {

		KeyListener editedKeyListener = new KeyListener() {

			@Override
			public void keyTyped(KeyEvent arg0) {
			}

			@Override
			public void keyReleased(KeyEvent arg0) {
			}

			@Override
			public void keyPressed(KeyEvent arg0) {
				edited = true;
			}
		};

		jwtST.getJwtPayloadArea().addKeyListener(editedKeyListener);

		ActionListener dontModifyListener = e -> radioButtonChanged(true, false, false, false, false);
		ActionListener randomKeyListener = e -> radioButtonChanged(false, true, false, false, false);
		ActionListener originalSignatureListener = e -> radioButtonChanged(false, false, true, false, false);
		ActionListener recalculateSignatureListener = e -> radioButtonChanged(false, false, false, true, false);
		ActionListener chooseSignatureListener = e -> radioButtonChanged(false, false, false, false, true);
		ActionListener algAttackListener = e -> algAttackChanged();
		ActionListener cveAttackListener = e -> cveAttackChanged();

		DocumentListener jwtKeyChanged = new DelayedDocumentListener(new DocumentListener() {

			@Override
			public void insertUpdate(DocumentEvent e) {
				signKeyChange();
			}

			@Override
			public void removeUpdate(DocumentEvent e) {
				signKeyChange();
			}

			@Override
			public void changedUpdate(DocumentEvent e) {
			}
		});

		KeyListener jwtAreaTyped = new KeyListener() {

			@Override
			public void keyTyped(KeyEvent e) {
			}

			@Override
			public void keyPressed(KeyEvent e) {
			}

			@Override
			public void keyReleased(KeyEvent e) {
				handleJWTAreaTyped();
			}
		};

		jwtST.registerActionListeners(dontModifyListener, randomKeyListener, originalSignatureListener, recalculateSignatureListener, chooseSignatureListener, algAttackListener, cveAttackListener,
				jwtKeyChanged, jwtAreaTyped);
	}
}

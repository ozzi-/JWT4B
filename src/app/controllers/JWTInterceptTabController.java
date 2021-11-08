package app.controllers;

import java.awt.Component;
import java.awt.FileDialog;
import java.awt.Frame;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.awt.event.KeyListener;
import java.io.UnsupportedEncodingException;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.List;

import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.SwingUtilities;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

import app.helpers.DelayedDocumentListener;
import com.auth0.jwt.algorithms.Algorithm;
import com.eclipsesource.json.Json;
import com.eclipsesource.json.JsonObject;

import app.algorithm.AlgorithmLinker;
import app.controllers.ReadableTokenFormat.InvalidTokenFormat;
import app.helpers.Config;
import app.helpers.Output;
import app.helpers.PublicKeyBroker;
import app.tokenposition.ITokenPosition;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IMessageEditorTab;
import gui.JWTInterceptTab;
import model.CustomJWToken;
import model.JWTInterceptModel;
import model.Settings;
import model.Strings;
import model.TimeClaim;


// used in the proxy intercept and repeater tabs
public class JWTInterceptTabController implements IMessageEditorTab {

	private JWTInterceptModel jwtIM;
	private JWTInterceptTab jwtST;
	private IExtensionHelpers helpers;
	private byte[] message;
	private ITokenPosition tokenPosition;
	private boolean isModified;

	public JWTInterceptTabController(IBurpExtenderCallbacks callbacks, JWTInterceptModel jwIM, JWTInterceptTab jwtST) {
		this.jwtIM = jwIM;
		this.jwtST = jwtST;
		this.helpers = callbacks.getHelpers();
		
		createAndRegisterActionListeners(jwtST);
	}


	// Callback for Algorithm ComboBox - changes algorithm and updates view
	private void changeAlgorithm() {
		Output.output("changeAlgorithm()");
		isModified = true;

		String algorithm = (String)jwtST.getAlgorithmComboBox().getSelectedItem();
		CustomJWToken token = null;
		try {
			token = ReadableTokenFormat.getTokenFromReadableFormat(jwtIM.getJWTJSON());
			String header = token.getHeaderJson();
			token.setHeaderJson(header.replace(token.getAlgorithm(), algorithm));
			// TODO: always remove signature if none algo?
//			if(AlgorithmLinker.isNoneAlgorithm(algorithm)){
//				token.setSignature("");
//			}

			jwtIM.setJWTJSON(ReadableTokenFormat.getReadableFormat(token));
			jwtIM.setSignature(token.getSignature());
			jwtST.updateSetView(false);
		} catch (InvalidTokenFormat e) {
			e.printStackTrace();
			Output.outputError("Exception: " + e.getMessage());
		}
	}

	private void loadKeyFile() {
		FileDialog dialog = new FileDialog((Frame) null, "Select file to open");
		dialog.setMode(FileDialog.LOAD);
		dialog.setVisible(true);
		if(dialog.getFile()!=null) {
			String file = dialog.getDirectory() + dialog.getFile();
			Output.output(file + " chosen.");
			String chosen = Strings.filePathToString(file);
			jwtIM.setJWTKey(chosen);
			jwtST.updateSetView(false);
		}
	}

	private RSAPublicKey loadPublicKey() {
		String publicPEM = Config.cveAttackModePublicKey.replaceAll("\\n", "").replace("-----BEGIN PUBLIC KEY-----", "")
				.replace("-----END PUBLIC KEY-----", "");
		;
		KeyFactory kf;
		try {
			kf = KeyFactory.getInstance("RSA");
			X509EncodedKeySpec keySpecX509 = new X509EncodedKeySpec(Base64.getDecoder().decode(publicPEM));
			return (RSAPublicKey) kf.generatePublic(keySpecX509);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	private void generateRandomKey() {
		SwingUtilities.invokeLater(new Runnable() {
			@Override
			public void run() {
				CustomJWToken token = null;
				try {
					token = ReadableTokenFormat.getTokenFromReadableFormat(jwtST.getJWTfromArea());
					String algorithm = token.getAlgorithm();

					if(AlgorithmLinker.isNoneAlgorithm(algorithm)){
						jwtIM.setJWTKey("");
					} else {
						Output.output("Generating Random Key");
						String randomKey = AlgorithmLinker.getRandomKey(algorithm);
						Output.output("RandomKey generated: " + randomKey);
						jwtIM.setJWTKey(randomKey);
					}

//					jwtIM.setJWTJSON(ReadableTokenFormat.getReadableFormat(token));
//					jwtIM.setSignature(token.getSignature());
					jwtST.updateSetView(false);

				} catch (InvalidTokenFormat invalidTokenFormat) {
					Output.outputError("InvalidTokenFormat: " + token!=null ? token.getAlgorithm() : "null");
					invalidTokenFormat.printStackTrace();
				}
			}
		});
	}

	@Override
	public boolean isEnabled(byte[] content, boolean isRequest) {
		return ITokenPosition.findTokenPositionImplementation(content, isRequest, helpers) != null;
	}

	@Override
	public void setMessage(byte[] content, boolean isRequest) {
		Output.output("setMessage()");
		isModified = false;
		tokenPosition = ITokenPosition.findTokenPositionImplementation(content, isRequest, helpers);
		jwtIM.setcFW(tokenPosition.getcFW());
		if (tokenPosition == null) {
			jwtST.updateSetView(true);
		} else {
			String rawToken = tokenPosition.getToken();
			CustomJWToken cJWT = new CustomJWToken(rawToken);
			List<TimeClaim> tcl = cJWT.getTimeClaimList();
			jwtIM.setTimeClaims(tcl);
			jwtIM.setJWTJSON(ReadableTokenFormat.getReadableFormat(cJWT));
			jwtIM.setSignature(cJWT.getSignature());

			jwtST.updateSetView(Config.resetEditor);
//			if(Config.resetEditor) {
				// TODO: disable combobox to avoid triggering handler
//				jwtST.getAlgorithmComboBox().setSelectedIndex(0);
//			}
		}
		this.message = content;
	}


	public void updateSignature() {
		Output.output("updateSignature()");
		isModified = true;

		String algorithm;
		try {
			CustomJWToken token = ReadableTokenFormat.getTokenFromReadableFormat(jwtST.getJWTfromArea());
			algorithm = token.getAlgorithm();

			if(AlgorithmLinker.isNoneAlgorithm(algorithm)){
				token.setSignature("");
			} else {
				String cleanKey = jwtST.getKeyFieldValue().replace("-----BEGIN PRIVATE KEY-----", "").replace("-----END PRIVATE KEY-----", "");
				//jwtIM.setJWTKey(cleanKey);

				Output.output("Recalculating Signature with Secret - '" + cleanKey + "'");
				token.calculateAndSetSignature(AlgorithmLinker.getSignerAlgorithm(algorithm, cleanKey));

				// TODO: add toggle for this?
				//  addLogHeadersToRequest();
			}

			// TODO: any other jwtIM values to update?
			jwtIM.setJWTJSON(ReadableTokenFormat.getReadableFormat(token));
			jwtIM.setSignature(token.getSignature());
			jwtST.updateSetView(false);
		} catch (IllegalArgumentException | UnsupportedEncodingException | InvalidTokenFormat e) {
			Output.outputError(e.getStackTrace().toString());
		}
	}

	private void parseAndUpdateToken() {
		CustomJWToken token;
		try {
			token = ReadableTokenFormat.getTokenFromReadableFormat(jwtST.getJWTfromArea());
			jwtIM.setJWTJSON(ReadableTokenFormat.getReadableFormat(token));
			jwtIM.setSignature(token.getSignature());
			jwtST.updateSetView(false);
		} catch (InvalidTokenFormat e) {
			e.printStackTrace();
			Output.output("Exception: " + e.getMessage());
			//TODO: show warning in UI
		}
	}

	private void updateKey() {
		jwtIM.setJWTKey(jwtST.getKeyFieldValue());
	}


	// TODO: re-add cve Attack
//		if (cveAttackMode) {
//			edited = true;
//			Output.output("CVE Attack mode");
//			String headerJSON = token.getHeaderJson();
//			JsonObject headerJSONObj = Json.parse(headerJSON).asObject();
//			headerJSONObj.set("alg", "RS256");
//			JsonObject jwk = new JsonObject();
//			jwk.add("kty", "RSA");
//			jwk.add("kid", "jwt4b@portswigger.net");
//			jwk.add("use", "sig");
//			RSAPublicKey pk = loadPublicKey();
//			jwk.add("n", Base64.getUrlEncoder().encodeToString(pk.getPublicExponent().toByteArray()));
//			jwk.add("e", Base64.getUrlEncoder().encodeToString(pk.getModulus().toByteArray()));
//			headerJSONObj.add("jwk", jwk);
//			token.setHeaderJson(headerJSONObj.toString());
//			Algorithm algo;
//			try {
//				algo = AlgorithmLinker.getSignerAlgorithm(token.getAlgorithm(), Config.cveAttackModePrivateKey);
//				token.calculateAndSetSignature(algo);
//			} catch (UnsupportedEncodingException e) {
//				Output.outputError("Failed to sign when using cve attack mode");
//				e.printStackTrace();
//			}
//		}


	@Override
	public byte[] getMessage() {
		// see https://github.com/PortSwigger/example-custom-editor-tab/blob/master/java/BurpExtender.java#L119

		CustomJWToken token = null;
		try {
			// jwtIM.JWTJson is 'the' source of truth for our current state
			token = ReadableTokenFormat.getTokenFromReadableFormat(jwtIM.getJWTJSON());
		} catch (InvalidTokenFormat e) {
			e.printStackTrace();
			Output.outputError("Exception: [getMessage()] " + e.getMessage());
		}
		// token may be null, if it is invalid JSON, if so, don't try changing anything
		// TODO: what to return if token failes to validate? last valid state/original message?
		if(token.getToken()!=null) {
			this.message = this.tokenPosition.replaceToken(token.getToken());
		}
		return this.message;
	}

	private void addLogHeadersToRequest() {
		this.tokenPosition.cleanJWTHeaders();
		this.tokenPosition.addHeader(Strings.JWTHeaderInfo);
		this.tokenPosition.addHeader(Strings.JWTHeaderPrefix + "SIGNER-KEY " + jwtIM.getJWTKey());
		if (PublicKeyBroker.publicKey != null) {
			this.tokenPosition.addHeader(Strings.JWTHeaderPrefix + "SIGNER-PUBLIC-KEY " + PublicKeyBroker.publicKey);
			PublicKeyBroker.publicKey = null;
		}
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
	public boolean isModified() {
		return isModified;
	}

	@Override
	public byte[] getSelectedData() {
		return jwtST.getSelectedData().getBytes();
	}
	
	private void createAndRegisterActionListeners(JWTInterceptTab jwtST) {

		ActionListener randomKeyListener = new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				generateRandomKey();
			}
		};

		ActionListener updateSignatureListener = new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				updateSignature();
			}
		};

		ActionListener changeAlgorithmListener = new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				changeAlgorithm();
			}
		};

		DocumentListener jwtChangeListener = new DelayedDocumentListener(new DocumentListener() {
			@Override
			public void insertUpdate(DocumentEvent e) {
				isModified = true;
				parseAndUpdateToken();
			}

			@Override
			public void removeUpdate(DocumentEvent e) {
				isModified = true;
				parseAndUpdateToken();
			}

			@Override
			public void changedUpdate(DocumentEvent e) {
				isModified = true;
				parseAndUpdateToken();
			}
		});

		DocumentListener keyChangeListener = new DelayedDocumentListener(new DocumentListener() {
			@Override
			public void insertUpdate(DocumentEvent e) {
				updateKey();
			}

			@Override
			public void removeUpdate(DocumentEvent e) {
				updateKey();
			}

			@Override
			public void changedUpdate(DocumentEvent e) {
				updateKey();
			}
		});

		jwtST.registerActionListeners(changeAlgorithmListener, randomKeyListener, updateSignatureListener, jwtChangeListener, keyChangeListener);
	}
}

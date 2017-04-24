package app.controllers;

import java.awt.Component;
import java.io.UnsupportedEncodingException;
import java.util.Observable;

import javax.swing.JTabbedPane;
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
import burp.ITab;
import gui.JWTSuiteTab;
import model.JWTSuiteTabModel;

public class JWTSuiteTabController extends Observable implements ITab {

	private JWTSuiteTabModel jwtSTM;
	private JWTSuiteTab jwtST;

	public JWTSuiteTabController(JWTSuiteTabModel jwtSTM, JWTSuiteTab jwtST) {
		this.jwtSTM = jwtSTM;
		this.jwtST = jwtST;

		DocumentListener jwtDocInputListener = new DocumentListener() {
			@Override
			public void removeUpdate(DocumentEvent e) {
				jwtSTM.setJwtInput(jwtST.getJWTInput());
				contextActionJWT(jwtSTM.getJwtInput(),false);
			}
			@Override
			public void insertUpdate(DocumentEvent e) {
				jwtSTM.setJwtInput(jwtST.getJWTInput());
				contextActionJWT(jwtSTM.getJwtInput(),false);
			}
			@Override
			public void changedUpdate(DocumentEvent e) {
			}
		};
		DocumentListener jwtDocKeyListener = new DocumentListener() {
			@Override
			public void removeUpdate(DocumentEvent e) {
				jwtSTM.setJwtKey(jwtST.getKeyInput());
				contextActionKey(jwtSTM.getJwtKey());
			}
			@Override
			public void insertUpdate(DocumentEvent e) {
				jwtSTM.setJwtKey(jwtST.getKeyInput());
				contextActionKey(jwtSTM.getJwtKey());
			}
			@Override
			public void changedUpdate(DocumentEvent e) {
			}
		};

		jwtST.registerDocumentListener(jwtDocInputListener, jwtDocKeyListener);
	}

	@Override
	public String getTabCaption() {
		return Settings.tabname;
	}

	@Override
	public Component getUiComponent() {
		return jwtST;
	}

	// This method was copied from
	// https://support.portswigger.net/customer/portal/questions/16743551-burp-extension-get-focus-on-tab-after-custom-menu-action
	public void selectJWTSuiteTab() {
		Component current = this.getUiComponent();
		do {
			current = current.getParent();
		} while (!(current instanceof JTabbedPane));

		JTabbedPane tabPane = (JTabbedPane) current;
		for (int i = 0; i < tabPane.getTabCount(); i++) {
			if (tabPane.getTitleAt(i).equals(this.getTabCaption()))
				tabPane.setSelectedIndex(i);
		}
	}

	private String getCurrentAlgorithm() {
		String str = "";
		try{
			str = new CustomJWToken(jwtSTM.getJwtInput()).getAlgorithm();
		}catch(Exception e){
			
		}
		return str;
	}

	public void contextActionJWT(String jwts,boolean fromContextMenu) {
		jwts = jwts.replace("Authorization:", "");
		jwts = jwts.replace("Bearer", "");
		jwts = jwts.replaceAll("\\s", "");
		jwtSTM.setJwtInput(jwts);
		try {
			CustomJWToken jwt = new CustomJWToken(jwts);
			jwtSTM.setJwtJSON(ReadableTokenFormat.getReadableFormat(jwt));
		} catch (Exception e) {
			// TODO handle invalid tokens in GUI
			ConsoleOut.output("JWT Context Action"+e.getMessage());
		}
		if(fromContextMenu){
			// Reset View and Select
			jwtSTM.setJwtKey("");
			selectJWTSuiteTab();
		}else{
			// Since we changed the JWT, we need to check the Key/Signature too
			contextActionKey(jwtSTM.getJwtKey());
		}
		jwtST.updateSetView();
	}

	public void contextActionKey(String key) {
		jwtSTM.setJwtKey(key);
		String curAlgo = getCurrentAlgorithm();
		try {
			JWTVerifier verifier = JWT.require(AlgorithmLinker.getVerifierAlgorithm(curAlgo, key)).build();
			DecodedJWT test = verifier.verify(jwtSTM.getJwtInput());
			jwtSTM.setJwtSignatureColor(Settings.colorValid);
			// TODO Strings.verificationValid;
			test.getAlgorithm();
		} catch (JWTVerificationException e) {
			ConsoleOut.output("Verification failed (" + e.getMessage() + ")");
			jwtSTM.setJwtSignatureColor(Settings.colorInvalid);
			// Strings.verificationWrongKey;
		} catch (IllegalArgumentException | UnsupportedEncodingException e) {
			ConsoleOut.output("Verification failed (" + e.getMessage() + ")");
			jwtSTM.setJwtSignatureColor(Settings.colorProblemInvalid);
			// Strings.verificationInvalidKey;
		}
		
		jwtST.updateSetView();
	}

}

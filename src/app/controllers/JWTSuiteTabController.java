package app.controllers;

import java.awt.Color;
import java.awt.Component;
import java.awt.event.KeyEvent;
import java.awt.event.KeyListener;
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
import app.helpers.CustomJWTToken;
import app.helpers.Settings;
import app.helpers.Strings;
import burp.ITab;
import gui.JWTSuiteTab;
import model.JWTSuiteTabModel;

public class JWTSuiteTabController extends Observable implements ITab {

	private String verificationResult;
	private Color verificationResultColor;
	private JWTSuiteTabModel jwtSTM;
	private JWTSuiteTab jwtST;

	public JWTSuiteTabController(JWTSuiteTabModel jwtSTM, JWTSuiteTab jwtST) {
		this.jwtSTM = jwtSTM;
		this.jwtST = jwtST;

		KeyListener jwtInputListener = new KeyListener() {

			@Override
			public void keyTyped(KeyEvent e) {
				contextActionJWT(jwtSTM.getJwtInput());
			}

			@Override
			public void keyReleased(KeyEvent e) {

			}

			@Override
			public void keyPressed(KeyEvent e) {
			}
		};

		KeyListener jwtKeyListener = new KeyListener() {

			@Override
			public void keyTyped(KeyEvent e) {
				contextActionKey(jwtSTM.getJwtKey());
			}

			@Override
			public void keyReleased(KeyEvent e) {
			}

			@Override
			public void keyPressed(KeyEvent e) {
			}
		};

		jwtST.registerDocumentListener(jwtInputListener, jwtKeyListener);
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
		return new CustomJWTToken(jwtSTM.getJwtInput()).getAlgorithm();
	}

	public void contextActionJWT(String jwts) {
		jwts = jwts.replace("Authorization:", "");
		jwts = jwts.replace("Bearer", "");
		jwts = jwts.replaceAll("\\s", "");
		jwtSTM.setJwtInput(jwts);
		contextActionKey(jwtSTM.getJwtInput());
		try {
			CustomJWTToken jwt = new CustomJWTToken(jwts);
			jwtSTM.setJwtJSON(ReadableTokenFormat.getReadableFormat(jwt));
		} catch (Exception e) {
			// TODO handle invalid tokens in GUI
			ConsoleOut.output(e.getMessage());
		}
		jwtST.updateSetView();
		selectJWTSuiteTab();
	}

	public void contextActionKey(String key) {
		String jwtTokenString = jwtSTM.getJwtInput();
		String curAlgo = getCurrentAlgorithm();
		try {
			JWTVerifier verifier = JWT.require(AlgorithmLinker.getAlgorithm(curAlgo, key)).build();
			DecodedJWT test = verifier.verify(jwtTokenString);
			this.verificationResult = Strings.verificationValid;
			this.verificationResultColor = Settings.colorValid;
			test.getAlgorithm();
		} catch (JWTVerificationException e) {
			ConsoleOut.output("Verification failed (" + e.getMessage() + ")");
			this.verificationResult = Strings.verificationWrongKey;
			this.verificationResultColor = Settings.colorInvalid;
		} catch (IllegalArgumentException | UnsupportedEncodingException e) {
			ConsoleOut.output("Verification failed (" + e.getMessage() + ")");
			this.verificationResult = Strings.verificationInvalidKey;
			this.verificationResultColor = Settings.colorProblemInvalid;
		}
		jwtSTM.setJwtSignatureColor(this.verificationResultColor);
		jwtST.updateSetView();
	}

}

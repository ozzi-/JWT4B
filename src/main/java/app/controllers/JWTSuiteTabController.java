package app.controllers;

import java.awt.Component;
import java.util.List;

import javax.swing.JTabbedPane;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

import app.algorithm.AlgorithmWrapper;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.exceptions.InvalidClaimException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;

import app.helpers.Output;
import gui.JWTSuiteTab;
import model.CustomJWToken;
import model.JWTSuiteTabModel;
import model.Settings;
import model.Strings;
import model.TimeClaim;

// used to provide the standalone suite tab after "User Options"
public class JWTSuiteTabController {

	private final JWTSuiteTabModel jwtSTM;
	private final JWTSuiteTab jwtST;

	public JWTSuiteTabController(final JWTSuiteTabModel jwtSTM, final JWTSuiteTab jwtST) {
		this.jwtSTM = jwtSTM;
		this.jwtST = jwtST;

		createAndRegisterActionListeners(jwtSTM, jwtST);
	}

	// This method was copied from
	// https://support.portswigger.net/customer/portal/questions/16743551-burp-extension-get-focus-on-tab-after-custom-menu-action
	public void selectJWTSuiteTab() {
		Component current = jwtST;
		do {
			current = current.getParent();
		} while (!(current instanceof JTabbedPane));

		JTabbedPane tabPane = (JTabbedPane) current;
		for (int i = 0; i < tabPane.getTabCount(); i++) {
			if (tabPane.getTitleAt(i).equals(Settings.TAB_NAME))
				tabPane.setSelectedIndex(i);
		}
	}

	public void contextActionSendJWTtoSuiteTab(String jwts, boolean fromContextMenu) {
		jwts = jwts.replace("Authorization:", "");
		jwts = jwts.replace("Bearer", "");
		jwts = jwts.replace("Set-Cookie: ", "");
		jwts = jwts.replace("Cookie: ", "");
		jwts = jwts.replaceAll("\\s", "");
		jwtSTM.setJwtInput(jwts);
		try {
			CustomJWToken jwt = new CustomJWToken(jwts);
			List<TimeClaim> tcl = jwt.getTimeClaimList();
			jwtSTM.setTimeClaims(tcl);
			jwtSTM.setJwtJSON(ReadableTokenFormat.getReadableFormat(jwt));
		} catch (Exception e) {
			Output.outputError("JWT Context Action: " + e.getMessage());
		}
		if (fromContextMenu) {
			// Reset View and Select
			jwtSTM.setJwtKey("");
			selectJWTSuiteTab();
		} else {
			// Since we changed the JWT, we need to check the Key/Signature too
			contextActionKey(jwtSTM.getJwtKey());
		}
		jwtST.updateSetView();
	}

	public void contextActionKey(String key) {
		jwtSTM.setJwtKey(key);
		jwtSTM.setVerificationResult("");
		try {
			CustomJWToken token = new CustomJWToken(jwtSTM.getJwtInput());
			String curAlgo = token.getAlgorithm();
			JWTVerifier verifier = JWT.require(AlgorithmWrapper.getVerifierAlgorithm(curAlgo, key)).build();
			DecodedJWT test = verifier.verify(token.getToken());
			jwtSTM.setJwtSignatureColor(Settings.getValidColor());
			jwtSTM.setVerificationLabel(Strings.VALID_VERFICIATION);
			test.getAlgorithm();
		} catch (JWTVerificationException e) {
			Output.output("Verification failed (" + e.getMessage() + ")");
			jwtSTM.setVerificationResult(e.getMessage());

			if (e instanceof SignatureVerificationException) {
				jwtSTM.setJwtSignatureColor(Settings.getInvalidColor());
				jwtSTM.setVerificationLabel(Strings.INVALID_SIGNATURE_VERIFICATION);
			} else if (e instanceof InvalidClaimException) {
				jwtSTM.setJwtSignatureColor(Settings.getProblemColor());
				jwtSTM.setVerificationLabel(Strings.INVALID_CLAIM_VERIFICATION);
			} else {
				jwtSTM.setJwtSignatureColor(Settings.getProblemColor());
				jwtSTM.setVerificationLabel(Strings.GENERIC_ERROR_VERIFICATION);
			}

		} catch (IllegalArgumentException e) {
			Output.output("Verification failed (" + e.getMessage() + ")");
			jwtSTM.setJwtSignatureColor(Settings.getProblemColor());
			jwtSTM.setVerificationResult(e.getMessage());
			jwtSTM.setVerificationLabel(Strings.INVALID_KEY_VERIFICATION);
		}
		jwtST.updateSetView();
	}

	private void createAndRegisterActionListeners(final JWTSuiteTabModel jwtSTM, final JWTSuiteTab jwtST) {
		DocumentListener jwtDocInputListener = new DocumentListener() {

			@Override
			public void removeUpdate(DocumentEvent e) {
				propagateUpdate(jwtSTM, jwtST);
			}

			@Override
			public void insertUpdate(DocumentEvent e) {
				propagateUpdate(jwtSTM, jwtST);
			}

			private void propagateUpdate(final JWTSuiteTabModel jwtSTM, final JWTSuiteTab jwtST) {
				jwtSTM.setJwtInput(jwtST.getJWTInput());
				contextActionSendJWTtoSuiteTab(jwtSTM.getJwtInput(), false);
			}

			@Override
			public void changedUpdate(DocumentEvent ignored) {
				// not required
			}
		};
		DocumentListener jwtDocKeyListener = new DocumentListener() {

			@Override
			public void removeUpdate(DocumentEvent e) {
				propagateUpdate(jwtSTM, jwtST);
			}

			@Override
			public void insertUpdate(DocumentEvent e) {
				propagateUpdate(jwtSTM, jwtST);
			}

			private void propagateUpdate(final JWTSuiteTabModel jwtSTM, final JWTSuiteTab jwtST) {
				jwtSTM.setJwtKey(jwtST.getKeyInput());
				contextActionKey(jwtSTM.getJwtKey());
			}

			@Override
			public void changedUpdate(DocumentEvent ignored) {
				// not required
			}
		};

		jwtST.registerDocumentListener(jwtDocInputListener, jwtDocKeyListener);
	}
}

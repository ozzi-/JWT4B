package app;

import java.awt.Color;
import java.awt.Component;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.InvocationTargetException;
import java.security.*;
import java.util.Arrays;
import java.util.List;
import java.util.Observable;
import java.util.Observer;

import javax.swing.JPanel;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;

import app.algorithm.AlgorithmLinker;
import app.tokenposition.AuthorizationBearerHeader;
import app.tokenposition.ITokenPosition;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IMessageEditorTab;
import org.bouncycastle.util.encoders.Base64;

public class JWTMessageEditorTabController extends Observable implements IMessageEditorTab {

	private IExtensionHelpers helpers;
	private String jwtTokenString;
	private JPanel jwtTab;
	private byte[] message;
	private boolean isRequest;
	private ITokenPosition tokenPosition;
	private String state = "orignial token";
	private Color verificationResultColor = Color.GRAY;
	private String verificationResult = "";

	public JWTMessageEditorTabController(IBurpExtenderCallbacks callbacks) {
		this.helpers = callbacks.getHelpers();
	}

	@Override
	public String getTabCaption() {
		return Settings.tabname;
	}

	@Override
	public Component getUiComponent() {
		return this.jwtTab;
	}

	@Override
	public void addObserver(Observer o) {
		// awful solution, enables GetUiCompent() to work.
		this.jwtTab = (JPanel) o;
		super.addObserver(o);
	}

	@Override
	public boolean isEnabled(byte[] content, boolean isRequest) {
		return findTokenPositionImplementation(content, isRequest) != null;
	}

	private ITokenPosition findTokenPositionImplementation(byte[] content, boolean isRequest) {
		List<Class<? extends ITokenPosition>> implementations = Arrays.asList(AuthorizationBearerHeader.class);

		for (Class<? extends ITokenPosition> implClass : implementations) {
			try {
				ITokenPosition impl = (ITokenPosition) implClass.getConstructors()[0].newInstance();
				impl.setHelpers(helpers);
				impl.setMessage(content, isRequest);
				if (impl.positionFound()) {
					return impl;
				}
			} catch (InstantiationException | IllegalAccessException | IllegalArgumentException
					| InvocationTargetException | SecurityException e) {
				return null;
			}
		}
		return null;
	}

	@Override
	public void setMessage(byte[] content, boolean isRequest) {
		this.message = content;
		this.isRequest = isRequest;

		this.tokenPosition = findTokenPositionImplementation(content, isRequest);
		assert (this.tokenPosition == null);
		this.jwtTokenString = tokenPosition.getToken();

		setChanged();
		notifyObservers(NotifyTypes.all);
	}

	@Override
	public byte[] getMessage() {
		return message;
	}

	@Override
	public boolean isModified() {
		return false;
	}

	public CustomJWTToken getJwtToken() {
		return new CustomJWTToken(this.jwtTokenString);
	}

	public String getJwtTokenString() {
		return jwtTokenString;
	}

	public void checkKey(String key) {
		String curAlgo = getCurrentAlgorithm();
		try {
			JWTVerifier verifier = JWT.require(AlgorithmLinker.getAlgorithm(curAlgo, key)).build();
			@SuppressWarnings("unused")
			DecodedJWT test = verifier.verify(jwtTokenString);
			ConsoleOut.output("Verification okay");
			this.verificationResult = "Valid Signature";
			this.verificationResultColor = Color.GREEN;
			setChanged();
			notifyObservers(NotifyTypes.gui_signaturecheck);
		} catch (JWTVerificationException e) {
			ConsoleOut.output("Verification failed ");
			this.verificationResult = "Invalid Key / Signature";
			this.verificationResultColor = Color.RED;
			setChanged();
			notifyObservers(NotifyTypes.gui_signaturecheck);
		} catch (IllegalArgumentException | UnsupportedEncodingException e) {
			ConsoleOut.output("Verification failed due to illegal key material / unsupported encoding");
			this.verificationResult = "Unparsable Key";
			this.verificationResultColor = Color.YELLOW;
			setChanged();
			notifyObservers(NotifyTypes.gui_signaturecheck);
		}
	}

	@Override
	public byte[] getSelectedData() {
		// TODO Auto-generated method stub
		return null;
	}

	private void updateToken(String token) {
		this.jwtTokenString = token;
		this.message = this.tokenPosition.replaceToken(this.jwtTokenString);
	}

	public String getCurrentAlgorithm() {
		return new CustomJWTToken(this.jwtTokenString).getAlgorithm();
	}

	public void changeAlgorithm(String algorithm, Boolean recalculateSignature, String signatureKey) {
		updateToken(
				TokenManipulator.changeAlgorithm(this.jwtTokenString, algorithm, recalculateSignature, signatureKey.split("-------")[0]));

		setChanged();
		notifyObservers(NotifyTypes.gui_algorithm);
	}

	public String getState() {
		return state;
	}

	public void setChangedToken(String userFormattedToken) {
		try {
			CustomJWTToken newToken = ReadableTokenFormat.getTokenFromReadableFormat(userFormattedToken);
			updateToken(newToken.getToken());
			this.state = "Token updated";
			this.verificationResultColor = Color.GREEN;
		} catch (ReadableTokenFormat.InvalidTokenFormat e) {
			this.state = e.getMessage();
			this.verificationResultColor = Color.RED;
			this.verificationResult = "";
		}
		setChanged();
		notifyObservers(NotifyTypes.gui_token);

	}

	public String getFormatedToken() {
		return ReadableTokenFormat.getReadableFormat(this.getJwtToken());
	}

	public Color getVerificationStatusColor() {
		return this.verificationResultColor;
	}

	public String generateKeyPair() {
		try {
			KeyPair pair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
			return adn(Base64.toBase64String(pair.getPrivate().getEncoded())) +
					"\n\n-------\n\n" +
					adn(Base64.toBase64String(pair.getPublic().getEncoded()));
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return "no success";
	}

	private String adn(String si) {
		String result = "";
		for (String s : si.split("(?<=\\G.{25})")) {
			result += s;
			result += "\n";
		}
		System.out.println(result);
		return result;
	}

	public String getVerificationResult() {
		return verificationResult;
	}

}

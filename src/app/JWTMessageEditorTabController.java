package app;

import java.awt.Component;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.InvocationTargetException;
import java.util.Arrays;
import java.util.List;
import java.util.Observable;
import java.util.Observer;

import javax.swing.JPanel;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;

import app.tokenposition.AuthorizationBearerHeader;
import app.tokenposition.ITokenPosition;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IMessageEditorTab;

public class JWTMessageEditorTabController extends Observable implements IMessageEditorTab {

	private IExtensionHelpers helpers;
	private String jwtTokenString;
	private JPanel jwtTab;
	private byte[] message;
	private boolean isRequest;
	private ITokenPosition tokenPosition;
	private String state = "orignial token";

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
		notifyObservers();
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
		// TODO get real algo
		try {
			JWTVerifier verifier = JWT.require(Algorithm.HMAC256(key)).build();
			DecodedJWT a = verifier.verify(jwtTokenString);
			System.out.println("SIG OK");
		} catch (JWTVerificationException e) {
			System.out.println("NOK - verification ");
			e.printStackTrace();
		} catch (IllegalArgumentException | UnsupportedEncodingException e) {
			e.printStackTrace();
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
				TokenManipulator.changeAlgorithm(this.jwtTokenString, algorithm, recalculateSignature, signatureKey));

		setChanged();
		notifyObservers();
	}

	public String getState() {
		return state;
	}
	
	public void setChangedToken(String userFormattedToken) { 
		CustomJWTToken newToken = ReadableTokenFormat.getTokenFromReadableFormat(userFormattedToken);
		if(newToken == null) { 
			this.state = "Cannot read token in text field";
		} else { 
			updateToken(newToken.getToken());
			this.state = "Token updated";
		}
		setChanged();
		notifyObservers();
		
	}

	public String getFormatedToken() {
		return ReadableTokenFormat.getReadableFormat(this.getJwtToken());
	}
}

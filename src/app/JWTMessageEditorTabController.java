package app;

import java.awt.Component;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.Observable;
import java.util.Observer;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IMessageEditorTab;
import burp.IRequestInfo;
import burp.IResponseInfo;

import javax.swing.JPanel;

public class JWTMessageEditorTabController extends Observable implements IMessageEditorTab {

	private IExtensionHelpers helpers;
	private String jwtTokenString;
	private JPanel jwtTab;
	private byte[] message;
	private boolean isRequest;

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
		List<String> headers = isRequest ? helpers.analyzeRequest(content).getHeaders()
				: helpers.analyzeResponse(content).getHeaders();
		String jwt = JWTFinder.findJWTInHeaders(headers);

		return jwt != null;
	}

	@Override
	public void setMessage(byte[] content, boolean isRequest) {
		this.message = content;
		this.isRequest = isRequest;

		List<String> headers = isRequest ? helpers.analyzeRequest(content).getHeaders()
				: helpers.analyzeResponse(content).getHeaders();

		this.jwtTokenString = JWTFinder.findJWTInHeaders(headers);

		setChanged();
		notifyObservers();
	}

	@Override
	public byte[] getMessage() {
		List<String>  headers;
		int bodyOffset;
		
		if (isRequest) {
			IRequestInfo requestInfo = helpers.analyzeRequest(message);
			headers = requestInfo.getHeaders();
			bodyOffset = requestInfo.getBodyOffset();
		} else { 
			IResponseInfo responseInfo = helpers.analyzeResponse(message);
			headers = responseInfo.getHeaders();
			bodyOffset = responseInfo.getBodyOffset();
		}
		
		headers = replaceAuthorizationHeader(headers, this.jwtTokenString);
		return helpers.buildHttpMessage(headers, Arrays.copyOfRange(message, bodyOffset, message.length));
	}

	private List<String> replaceAuthorizationHeader(List<String> headers, String newToken) {
		LinkedList<String> newHeaders = new LinkedList<>();

		for (String h : headers) {
			if (h.startsWith("Authorization: Bearer ")) {
				newHeaders.add("Authorization: Bearer " + newToken);
			} else {
				newHeaders.add(h);
			}
		}
		return newHeaders;
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

	public String getFormatedToken() {
		CustomJWTToken token = this.getJwtToken();

		StringBuilder result = new StringBuilder();

		result.append("Headers = ");
		result.append(jsonBeautify(token.getHeaderJson()));

		result.append("\n\nPayload = ");
		result.append(jsonBeautify(token.getPayloadJson()));

		result.append("\n\nSignature = ");
		result.append(token.getSignature());
		return result.toString();

	}

	public void changeSingatureAlgorithmToNone() {
		this.jwtTokenString = TokenManipulator.setAlgorithmToNone(this.jwtTokenString);
		setChanged();
		notifyObservers();
	}
	
	private String jsonBeautify(String input) { 
		ObjectMapper objectMapper = new ObjectMapper();
		objectMapper.enable(SerializationFeature.INDENT_OUTPUT);

		JsonNode tree;
		String output;
		try {
			tree = objectMapper.readTree(input);
			 output = objectMapper.writeValueAsString(tree);
		} catch (IOException e) {
			return input;
		}
		return output;
	}
}

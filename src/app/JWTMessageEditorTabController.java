package app;

import java.awt.Component;
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

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IMessageEditorTab;
import burp.IRequestInfo;

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
		if(isRequest) { 
			IRequestInfo a = helpers.analyzeRequest(message);
			List<String> headers = a.getHeaders();
			headers = replaceAuthorizationHeader(headers, this.jwtTokenString);
			return helpers.buildHttpMessage(headers, Arrays.copyOfRange(message, a.getBodyOffset(), message.length));
		}
		return message;
	}

	private List<String> replaceAuthorizationHeader(List<String> headers, String newToken) {
		LinkedList<String> newHeaders = new LinkedList<>();
		
		for(String h : headers) { 
			if(h.startsWith("Authorization: Bearer ")) { 
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


	public JWT getJwtToken() {
		return new CustomJWTDecoder(this.jwtTokenString);
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
		}catch (IllegalArgumentException | UnsupportedEncodingException e) {
			e.printStackTrace();
		}
	}

	@Override
	public byte[] getSelectedData() {
		// TODO Auto-generated method stub
		return null;
	}
	
	public String getFormatedToken() {
		JWT token = this.getJwtToken();
		
		try { 
			StringBuilder result = new StringBuilder();
			
			
			result.append("Headers: \n");
			
			result.append("\tAlgorithm : ");
			result.append(token.getAlgorithm()).append('\n');
			
			result.append("Claims: \n");
			
			for (String key :token.getClaims().keySet()){ 
				result.append("\t" + key + ":" + token.getClaim(key).asString() + "\n");
			}
			
			result.append("Signature: \n");

			result.append("\tSignature : " + token.getSignature());
			return result.toString();
			
		} catch ( JWTDecodeException e)  {
			return e.getMessage();
		}
	}
	
	public void changeSingatureAlgorithmToNone() {
		this.jwtTokenString = TokenManipulator.setAlgorithmToNone(this.jwtTokenString);
		setChanged();
		notifyObservers();
	}
}

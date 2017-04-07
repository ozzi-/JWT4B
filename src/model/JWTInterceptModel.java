package model;

import java.awt.Color;

public class JWTInterceptModel{
	private String jwtInput;
	private String jwtKey;
	private String jwt;
	private Color jwtSignatureColor;
	private String jwtJSON;
	private String signature;
	private String originalSignature;
	
	public String getJWTInput() {
		return jwtInput;
	}
	public void setJWTInput(String jwtInput) {
		this.jwtInput = jwtInput;
	}
	public String getJWTKey() {
		return jwtKey;
	}
	public void setJWTKey(String jwtKey) {
		this.jwtKey = jwtKey;
	}
	public Color getJWTSignatureColor() {
		return jwtSignatureColor;
	}
	public void setJWTSignatureColor(Color jwtSignatureColor) {
		this.jwtSignatureColor = jwtSignatureColor;
	}
	public String getJWTJSON() {
		return jwtJSON;
	}
	public void setJWTJSON(String jwtJSON) {
		this.jwtJSON = jwtJSON;
	}
	public void setJWT(String jwt) {
		this.jwt = jwt;
		
	}
	public String getJWT() {
		return this.jwt;
	}
	public String getSignature() {
		return this.signature;
	}
	public void setSignature(String signature) {
		this.signature=signature;
		if(this.signature != null && !this.signature.isEmpty()){
			this.originalSignature=signature;
		}
	}
	public String getOriginalSignature() {
		return originalSignature;
	}

}
package model;

import java.awt.Color;
import java.util.List;

import app.helpers.CookieFlagWrapper;

public class JWTInterceptModel{
	private String jwtInput;
	private String jwtKey;
	private String jwt;
	private Color jwtSignatureColor;
	private String jwtJSON;
	private String signature;
	private String originalSignature;
	private String problemDetail;
	private CookieFlagWrapper cFW;
	private List<TimeClaim> tcl;
	
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
	public String getProblemDetail() {
		return problemDetail;
	}
	public void setProblemDetail(String problemDetail) {
		this.problemDetail = problemDetail;
	}
	public CookieFlagWrapper getcFW() {
		return cFW;
	}
	public void setcFW(CookieFlagWrapper cFW) {
		this.cFW = cFW;
	}
	public void setTimeClaims(List<TimeClaim> tcl) {
		this.tcl=tcl;		
	}
	public String getTimeClaimsAsText(){
		return TimeClaim.getTimeClaimsAsText(tcl);
	}
}
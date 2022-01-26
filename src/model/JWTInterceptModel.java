package model;

import java.util.List;

import app.tokenposition.ITokenPosition;

public class JWTInterceptModel {

  private String jwtSignatureKey;
  private CustomJWToken jwToken;
  private String originalJWT;
  private String problemDetail;
  private ITokenPosition tokenPosition;
  private List<TimeClaim> tcl;
  private CustomJWToken originalJWToken;

  public String getJWTKey() {
    return jwtSignatureKey;
  }

  public void setJWTSignatureKey(String jwtSignatureKey) {
    this.jwtSignatureKey = jwtSignatureKey;
  }

  public String getProblemDetail() {
    return problemDetail;
  }

  public void setProblemDetail(String problemDetail) {
    this.problemDetail = problemDetail;
  }

  public String getAdditionalDataAsHtml() {
    return tokenPosition.toHTMLString();
  }

  public void setTokenPosition(ITokenPosition tokenPosition) {
    this.tokenPosition = tokenPosition;
  }

  public void setTimeClaims(List<TimeClaim> tcl) {
    this.tcl = tcl;
  }

  public String getTimeClaimsAsText() {
    return TimeClaim.getTimeClaimsAsHTML(tcl);
  }

  public CustomJWToken getJwToken() {
    return jwToken;
  }

  public void setJwToken(CustomJWToken jwToken) {
    this.jwToken = jwToken;
  }

  public void setOriginalJWT(String originalJWT) {
    this.originalJWT = originalJWT;
  }

  public String getOriginalJWT() {
    return originalJWT;
  }

  public void setOriginalJWToken(CustomJWToken originalJWToken) {
    this.originalJWToken = originalJWToken;
  }

  public CustomJWToken getOriginalJWToken() {
    return originalJWToken;
  }
}
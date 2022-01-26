package model;

import java.awt.Color;
import java.util.List;

import app.tokenposition.ITokenPosition;

public class JWTTabModel {

  private String key = "";
  private String keyLabel = "";
  private int hashCode;
  private String verificationLabel = "";
  private Color verificationColor;
  private String jwt;
  private String jwtJSON;
  private ITokenPosition tokenPosition;
  private List<TimeClaim> tcl;

  public JWTTabModel() {
  }

  public JWTTabModel(String keyValue, byte[] content) {
    this.key = keyValue;
    this.hashCode = new String(content).hashCode();
    this.verificationColor = Settings.COLOR_UNDEFINED;
  }

  @Override
  public boolean equals(Object otherObj) {
    if (otherObj instanceof JWTTabModel) {
      JWTTabModel otherViewState = (JWTTabModel) otherObj;
      return (otherViewState.getHashCode() == this.getHashCode());
    }
    return false;
  }

  public String getKey() {
    return key;
  }

  public int getHashCode() {
    return hashCode;
  }

  public void setKeyValueAndHash(String keyValue, int hashCode) {
    this.key = keyValue;
    this.hashCode = hashCode;
  }

  public void setVerificationResult(String verificationResult) {
    this.verificationLabel = verificationResult;
  }

  public String getKeyLabel() {
    return keyLabel;
  }

  public void setKeyLabel(String keyLabel) {
    this.keyLabel = keyLabel;
  }

  public String getVerificationLabel() {
    return key.equals("") ? "" : verificationLabel;
  }

  public void setVerificationLabel(String verificationLabel) {
    this.verificationLabel = verificationLabel;
  }

  public Color getVerificationColor() {
    return key.equals("") ? Settings.COLOR_UNDEFINED : verificationColor;
  }

  public void setVerificationColor(Color verificationColor) {
    this.verificationColor = verificationColor;
  }

  public void setKey(String key) {
    this.key = key;
  }

  public void setHashCode(int hashCode) {
    this.hashCode = hashCode;
  }

  public void setJWT(String token) {
    this.jwt = token;
  }

  public String getJWT() {
    return jwt;
  }

  public String getJWTJSON() {
    return jwtJSON;
  }

  public void setJWTJSON(String readableFormat) {
    jwtJSON = readableFormat;
  }

  public void setTokenPosition(ITokenPosition tokenPosition) {
    this.tokenPosition = tokenPosition;
  }

  public String getAdditionalDataAsHtml() {
    return tokenPosition.toHTMLString();
  }

  public void setTimeClaims(List<TimeClaim> tcl) {
    this.tcl = tcl;
  }

  public String getTimeClaimsAsText() {
    return TimeClaim.getTimeClaimsAsHTML(tcl);
  }
}

package app.tokenposition;

public class Dummy extends ITokenPosition {

  public static final String CURLY_BRACKET_B64 = "e30=.";

  @Override
  public boolean positionFound() {
    return false;
  }

  @Override
  public String getToken() {
    return CURLY_BRACKET_B64 + CURLY_BRACKET_B64;
  }

  @Override
  public byte[] replaceToken(String newToken) {
    return (CURLY_BRACKET_B64 + CURLY_BRACKET_B64).getBytes();
  }

  @Override
  public String toHTMLString() {
    return "";
  }
}

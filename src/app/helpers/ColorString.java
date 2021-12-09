package app.helpers;

import java.awt.Color;

public class ColorString {

  private final Color color;
  private final String strng;

  ColorString(String strng, Color color) {
    this.strng = strng;
    this.color = color;
  }

  public String getStrng() {
    return strng;
  }

  public Color getColor() {
    return color;
  }
}

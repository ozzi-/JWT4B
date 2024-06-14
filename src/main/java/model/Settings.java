package model;

import java.awt.Color;

import javax.swing.JButton;

public class Settings {

  Settings() {
    
  }

  public static final String TAB_NAME = "JSON Web Tokens";
  public static final String EXTENSION_NAME = "JSON Web Tokens";

  public static boolean isLight = true;

  private static final Color COLOR_VALID_LIGHT = new Color(89, 207, 120);
  private static final Color COLOR_VALID_DARK = new Color(16, 48, 25);

  private static final Color COLOR_INVALID_LIGHT = new Color(199, 69, 60);
  private static final Color COLOR_INVALID_DARK = new Color(51, 9, 6);

  private static final Color COLOR_PROBLEM_INVALID_LIGHT = new Color(200, 204, 88);
  private static final Color COLOR_PROBLEM_INVALID_DARK = new Color(64, 62, 3);

  public static Color getValidColor() {
    if (isLight) {
      return COLOR_VALID_LIGHT;
    }
    return COLOR_VALID_DARK;
  }

  public static Color getInvalidColor() {
    if (isLight) {
      return COLOR_INVALID_LIGHT;
    }
    return COLOR_INVALID_DARK;
  }

  public static Color getProblemColor() {
    if (isLight) {
      return COLOR_PROBLEM_INVALID_LIGHT;
    }
    return COLOR_PROBLEM_INVALID_DARK;
  }

  public static final Color COLOR_UNDEFINED = new JButton().getBackground();
}

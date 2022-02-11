package gui;

import static java.awt.Color.WHITE;

import javax.swing.JLabel;

import burp.IBurpExtenderCallbacks;
import model.Settings;

public class ThemeDetector {

  private final IBurpExtenderCallbacks callbacks;

  ThemeDetector(IBurpExtenderCallbacks callbacks) {
    this.callbacks = callbacks;
  }

  boolean isLightTheme() {
    JLabel label = new JLabel();
    callbacks.customizeUiComponent(label);
    boolean isLight = label.getBackground().equals(WHITE);
    Settings.isLight = isLight; // TODO not so nice, since settings are static
    return isLight;
  }
}

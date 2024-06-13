package gui;

import static java.awt.Color.WHITE;

import javax.swing.JLabel;

import burp.api.montoya.ui.UserInterface;
import model.Settings;

public class ThemeDetector {

	private final UserInterface userInterface;

	ThemeDetector(UserInterface userInterface) {
		this.userInterface = userInterface;
	}

	boolean isLightTheme() {
		JLabel label = new JLabel();
		userInterface.applyThemeToComponent(label);
		boolean isLight = label.getBackground().equals(WHITE);
		Settings.isLight = isLight; // TODO not so nice, since settings are static
		return isLight;
	}
}

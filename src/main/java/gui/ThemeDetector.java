package gui;

import burp.api.montoya.ui.UserInterface;
import model.Settings;

import static burp.api.montoya.ui.Theme.LIGHT;

import java.awt.Font;

public class ThemeDetector {

	private final UserInterface userInterface;

	ThemeDetector(UserInterface userInterface) {
		this.userInterface = userInterface;
	}

	boolean isLightTheme() {
		boolean isLight = userInterface.currentTheme() == LIGHT;
		Settings.isLight = isLight; // TODO not so nice, since settings are static
		return isLight;
	}

}

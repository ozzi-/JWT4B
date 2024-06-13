package gui;

import static app.helpers.Output.outputError;

import java.io.IOException;

import burp.api.montoya.ui.UserInterface;
import org.fife.ui.rsyntaxtextarea.RSyntaxTextArea;
import org.fife.ui.rsyntaxtextarea.Theme;

public class RSyntaxTextAreaFactory {

	private final ThemeDetector themeDetector;

	public RSyntaxTextAreaFactory(UserInterface userInterface) {
		this.themeDetector = new ThemeDetector(userInterface);
	}

	RSyntaxTextArea rSyntaxTextArea() {
		return new BurpThemeAwareRSyntaxTextArea(themeDetector);
	}

	RSyntaxTextArea rSyntaxTextArea(int rows, int cols) {
		return new BurpThemeAwareRSyntaxTextArea(themeDetector, rows, cols);
	}

	private static class BurpThemeAwareRSyntaxTextArea extends RSyntaxTextArea {

		private static final long serialVersionUID = 1L;
		private static final String THEME_PATH = "/org/fife/ui/rsyntaxtextarea/themes/"; //NOSONAR
		private static final String DARK_THEME = THEME_PATH + "dark.xml";
		private static final String LIGHT_THEME = THEME_PATH + "default.xml";

		private final ThemeDetector themeDetector;

		private BurpThemeAwareRSyntaxTextArea(ThemeDetector themeDetector) {
			this.themeDetector = themeDetector;
			applyTheme();
		}

		public BurpThemeAwareRSyntaxTextArea(ThemeDetector themeDetector, int rows, int cols) {
			super(rows, cols);
			this.themeDetector = themeDetector;
			applyTheme();
		}

		@Override
		public void updateUI() {
			super.updateUI();

			if (themeDetector != null) {
				applyTheme();
			}
		}

		private void applyTheme() {
			String themeResource = themeDetector.isLightTheme() ? LIGHT_THEME : DARK_THEME;

			try {
				Theme theme = Theme.load(getClass().getResourceAsStream(themeResource));
				theme.apply(this);
			} catch (IOException e) {
				outputError("Unable to apply rsyntax theme: " + e.getMessage());
			}
		}
	}

}

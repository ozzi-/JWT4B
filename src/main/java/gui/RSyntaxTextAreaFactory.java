package gui;

import static app.helpers.Output.outputError;

import java.awt.event.MouseEvent;
import java.io.IOException;

import javax.swing.ToolTipManager;
import javax.swing.text.BadLocationException;

import app.helpers.TimeClaimTooltip;
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
			installTimeClaimTooltip();
		}

		public BurpThemeAwareRSyntaxTextArea(ThemeDetector themeDetector, int rows, int cols) {
			super(rows, cols);
			this.themeDetector = themeDetector;
			applyTheme();
			installTimeClaimTooltip();
		}

		/**
		 * Shows a human-readable tooltip when the mouse hovers the value of a JWT time claim
		 * (exp / nbf / iat). Routed through RSyntaxTextArea's focusable tip, which renders HTML
		 * in a JEditorPane (the standard Swing tooltip does not render HTML under Burp's look and feel).
		 */
		private void installTimeClaimTooltip() {
			ToolTipManager.sharedInstance().registerComponent(this);
			setUseFocusableTips(true);
			setToolTipSupplier((textArea, e) -> timeClaimTooltip(e));
		}

		private String timeClaimTooltip(MouseEvent e) {
			try {
				int offset = viewToModel2D(e.getPoint());
				if (offset >= 0) {
					int line = getLineOfOffset(offset);
					int lineStart = getLineStartOffset(line);
					String lineText = getText(lineStart, getLineEndOffset(line) - lineStart);
					TimeClaimTooltip.ClaimMatch match = TimeClaimTooltip.match(lineText);
					if (match != null) {
						int col = offset - lineStart;
						if (col >= match.valueStart && col <= match.valueEnd) {
							return TimeClaimTooltip.format(match, System.currentTimeMillis() / 1000L);
						}
					}
				}
			} catch (BadLocationException | RuntimeException ex) {
				// no tooltip for this position
			}
			return null;
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

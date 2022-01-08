package gui;

import burp.IBurpExtenderCallbacks;
import org.fife.ui.rsyntaxtextarea.RSyntaxTextArea;
import org.fife.ui.rsyntaxtextarea.Theme;

import javax.swing.*;
import java.io.IOException;

import static app.helpers.Output.outputError;
import static java.awt.Color.WHITE;

public class RSyntaxTextAreaFactory {
    private final ThemeDetector themeDetector;

    public RSyntaxTextAreaFactory(IBurpExtenderCallbacks callbacks) {
        this.themeDetector = new ThemeDetector(callbacks);
    }

    RSyntaxTextArea rSyntaxTextArea() {
        return new BurpThemeAwareRSyntaxTextArea(themeDetector);
    }

    RSyntaxTextArea rSyntaxTextArea(int rows, int cols) {
        return new BurpThemeAwareRSyntaxTextArea(themeDetector, rows, cols);
    }

    private static class BurpThemeAwareRSyntaxTextArea extends RSyntaxTextArea
    {
        private static final String DARK_THEME = "/org/fife/ui/rsyntaxtextarea/themes/dark.xml";
        private static final String LIGHT_THEME = "/org/fife/ui/rsyntaxtextarea/themes/default.xml";

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
                outputError(e.getMessage());
            }
        }
    }

    private static class ThemeDetector {
        private final IBurpExtenderCallbacks callbacks;

        private ThemeDetector(IBurpExtenderCallbacks callbacks) {
            this.callbacks = callbacks;
        }

        boolean isLightTheme() {
            JLabel label = new JLabel();
            callbacks.customizeUiComponent(label);

            return label.getBackground().equals(WHITE);
        }
    }
}

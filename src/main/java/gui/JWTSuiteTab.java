package gui;

import java.awt.Color;
import java.awt.Desktop;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.io.File;
import java.io.IOException;
import java.io.Serial;

import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JTextArea;
import javax.swing.SwingUtilities;
import javax.swing.UIManager;
import javax.swing.event.DocumentListener;
import javax.swing.text.JTextComponent;

import org.fife.ui.rsyntaxtextarea.RSyntaxTextArea;
import org.fife.ui.rsyntaxtextarea.Style;
import org.fife.ui.rsyntaxtextarea.SyntaxConstants;
import org.fife.ui.rsyntaxtextarea.SyntaxScheme;
import org.fife.ui.rsyntaxtextarea.Token;
import org.fife.ui.rtextarea.RTextScrollPane;

import app.helpers.Config;
import burp.api.montoya.MontoyaApi;
import model.JWTSuiteTabModel;
import model.Strings;

public class JWTSuiteTab extends JPanel {

	@Serial
	private static final long serialVersionUID = 1L;

	private JTextArea jwtInputField;
	private RSyntaxTextArea jwtOuputField;
	private JButton jwtSignatureButton;
	private JTextArea jwtKeyArea;
	private final JWTSuiteTabModel jwtSTM;
	private final RSyntaxTextAreaFactory rSyntaxTextAreaFactory;
	private JLabel lbRegisteredClaims;
	private JLabel lblExtendedVerificationInfo;
	private MontoyaApi api;
	private JLabel lblPasteJwtToken;
	private JLabel lblEnterSecret;
	private JLabel lblDecodedJwt;

	public JWTSuiteTab(JWTSuiteTabModel jwtSTM, RSyntaxTextAreaFactory rSyntaxTextAreaFactory, MontoyaApi api) {
		this.rSyntaxTextAreaFactory = rSyntaxTextAreaFactory;
		this.api = api;
		drawGui();
		this.jwtSTM = jwtSTM;
	}

	public void updateSetView() {
		SwingUtilities.invokeLater(() -> {
			if (!jwtInputField.getText().equals(jwtSTM.getJwtInput())) {
				jwtInputField.setText(jwtSTM.getJwtInput());
			}
			if (!jwtSignatureButton.getText().equals(jwtSTM.getVerificationLabel())) {
				jwtSignatureButton.setText(jwtSTM.getVerificationLabel());
			}
			if (!jwtOuputField.getText().equals(jwtSTM.getJwtJSON())) {
				jwtOuputField.setText(jwtSTM.getJwtJSON());
			}
			if (!jwtKeyArea.getText().equals(jwtSTM.getJwtKey())) {
				jwtKeyArea.setText(jwtSTM.getJwtKey());
			}
			if (!jwtSignatureButton.getBackground().equals(jwtSTM.getJwtSignatureColor())) {
				jwtSignatureButton.setBackground(jwtSTM.getJwtSignatureColor());
			}
			if (jwtKeyArea.getText().equals("")) {
				jwtSTM.setJwtSignatureColor(new JButton().getBackground());
				jwtSignatureButton.setBackground(jwtSTM.getJwtSignatureColor());
			}
			lblExtendedVerificationInfo.setText(jwtSTM.getVerificationResult());
			lbRegisteredClaims.setText(jwtSTM.getTimeClaimsAsText());
			jwtOuputField.setCaretPosition(0);
		});
	}

	public void registerDocumentListener(DocumentListener jwtInputListener, DocumentListener jwtKeyListener) {
		jwtInputField.getDocument().addDocumentListener(jwtInputListener);
		jwtKeyArea.getDocument().addDocumentListener(jwtKeyListener);
	}

	@Override
	public void updateUI() {
		if(api!=null) {
			SwingUtilities.invokeLater(() -> {
				Font currentFont = api.userInterface().currentDisplayFont();
				lblPasteJwtToken.setFont(currentFont);			
				lblEnterSecret.setFont(currentFont);
				lblDecodedJwt.setFont(currentFont);
				String lbRegClaimText = lbRegisteredClaims.getText();
				lbRegisteredClaims.putClientProperty("html.disable", false);
				lbRegisteredClaims.setText("<html>reinitializing needed for proper html display</html>");
				lbRegisteredClaims.setText(lbRegClaimText);
				jwtOuputField.setFont(currentFont);
			});
		}
	}
	
	private void drawGui() {
		Font currentFont = api.userInterface().currentDisplayFont();
		
		GridBagLayout gridBagLayout = new GridBagLayout();
		gridBagLayout.columnWidths = new int[] { 10, 0, 0, 0 };
		gridBagLayout.rowHeights = new int[] { 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
		gridBagLayout.columnWeights = new double[] { 0.0, 1.0, 0.0, Double.MIN_VALUE };
		gridBagLayout.rowWeights = new double[] { 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, Double.MIN_VALUE };
		setLayout(gridBagLayout);

		lblPasteJwtToken = new JLabel(Strings.ENTER_JWT);
		lblPasteJwtToken.setFont(currentFont);
		GridBagConstraints gbc_lblPasteJwtToken = new GridBagConstraints();
		gbc_lblPasteJwtToken.anchor = GridBagConstraints.SOUTHWEST;
		gbc_lblPasteJwtToken.insets = new Insets(0, 0, 5, 5);
		gbc_lblPasteJwtToken.gridx = 1;
		gbc_lblPasteJwtToken.gridy = 1;
		add(lblPasteJwtToken, gbc_lblPasteJwtToken);

		JButton creditButton = new JButton("About");
		creditButton.addActionListener(arg0 -> {
			JLabelLink jLabelLink = new JLabelLink(Strings.CREDIT_TITLE, 530, 625);

			jLabelLink.addText("<h2>About JWT4B</h2>JSON Web Tokens (also known as JWT4B) is developed by Oussama Zgheb<br>");
			jLabelLink.addURL("<a href=\"https://zgheb.com/\">Mantainer Website</a>", "zgheb.com");
			jLabelLink.addURL("<a href=\"https://github.com/ozzi-/JWT4B\">GitHub Repository</a>", "github.com/ozzi/JWT4B");
			jLabelLink.addText("<br>");
			jLabelLink.addText("JWT4B, excluding the libraries mentioned below and the Burp extender classes, uses the GPL 3 license.");
			jLabelLink.addURL("· <a href=\"https://github.com/bobbylight/RSyntaxTextArea/blob/master/src/main/dist/RSyntaxTextArea.License.txt\">RSyntaxTextArea</a>",
					"github.com/bobbylight/RSyntaxTextArea");
			jLabelLink.addURL("· <a href=\"https://github.com/auth0/java-jwt/blob/master/LICENSE\">Auth0 -java-jwt</a>", "github.com/auth0/java-jwt");
			jLabelLink.addURL("· <a href=\"https://www.apache.org/licenses/\">Apache Commons Lang</a>", "apache.org");
			jLabelLink.addText("<br>");
			jLabelLink.addText("Thanks to:<br>· Compass Security AG for providing development time for the initial version<br>");
			jLabelLink.addURL("&nbsp;&nbsp;<a href=\"https://www.compass-security.com\">compass-security.com</a><br>", "compass-security.com");
			jLabelLink.addText("· Brainloop for providing broader token support");
			jLabelLink.addURL("&nbsp;&nbsp;<a href=\"https://www.brainloop.com\">brainloop.com</a><br>", "brainloop.com");
			jLabelLink.addText("· Cyrill for the help porting JWT4B to the Montaya API");
			jLabelLink.addURL("&nbsp;&nbsp;<a href=\"https://github.com/bcyrill\">github.com/bcyrill</a><br><br>", "github.com/bcyrill");
			jLabelLink.addLogoImage();
		});
		GridBagConstraints gbc_creditButton = new GridBagConstraints();
		gbc_creditButton.insets = new Insets(0, 0, 5, 0);
		gbc_creditButton.gridx = 2;
		gbc_creditButton.gridy = 1;
		gbc_creditButton.fill = GridBagConstraints.HORIZONTAL;
		add(creditButton, gbc_creditButton);

		JButton configButton = new JButton("Change Config");
		configButton.addActionListener(arg0 -> {
			File file = new File(Config.configPath);
			Desktop desktop = Desktop.getDesktop();
			try {
				desktop.open(file);
			} catch (IOException e) {
				System.err.println("Error using Desktop API - " + e.getMessage() + " - " + e.getCause());
			}
		});

		GridBagConstraints gbc_configButton = new GridBagConstraints();
		gbc_configButton.insets = new Insets(0, 0, 5, 0);
		gbc_configButton.gridx = 2;
		gbc_configButton.gridy = 2;
		gbc_configButton.fill = GridBagConstraints.HORIZONTAL;
		add(configButton, gbc_configButton);

		jwtInputField = new JTextArea();
		jwtInputField.setBorder(UIManager.getLookAndFeel().getDefaults().getBorder("TextField.border"));
		jwtInputField.setRows(2);
		jwtInputField.setLineWrap(true);
		jwtInputField.setWrapStyleWord(true);

		GridBagConstraints gbc_jwtInputField = new GridBagConstraints();
		gbc_jwtInputField.insets = new Insets(0, 0, 5, 5);
		gbc_jwtInputField.fill = GridBagConstraints.BOTH;
		gbc_jwtInputField.gridx = 1;
		gbc_jwtInputField.gridy = 2;
		add(jwtInputField, gbc_jwtInputField);

		lblEnterSecret = new JLabel(Strings.ENTER_SECRET_KEY);
		lblEnterSecret.setFont(currentFont);
		GridBagConstraints gbc_lblEnterSecret = new GridBagConstraints();
		gbc_lblEnterSecret.anchor = GridBagConstraints.WEST;
		gbc_lblEnterSecret.insets = new Insets(0, 0, 5, 5);
		gbc_lblEnterSecret.gridx = 1;
		gbc_lblEnterSecret.gridy = 3;
		add(lblEnterSecret, gbc_lblEnterSecret);

		jwtKeyArea = new JTextArea();
		jwtKeyArea.setBorder(UIManager.getLookAndFeel().getDefaults().getBorder("TextField.border"));
		GridBagConstraints gbc_jwtKeyField = new GridBagConstraints();
		gbc_jwtKeyField.insets = new Insets(0, 0, 5, 5);
		gbc_jwtKeyField.fill = GridBagConstraints.HORIZONTAL;
		gbc_jwtKeyField.gridx = 1;
		gbc_jwtKeyField.gridy = 4;
		add(jwtKeyArea, gbc_jwtKeyField);
		jwtKeyArea.setColumns(10);

		jwtSignatureButton = new JButton("");
		Dimension preferredSize = new Dimension(400, 30);
		jwtSignatureButton.setPreferredSize(preferredSize);

		GridBagConstraints gbc_jwtSignatureButton = new GridBagConstraints();
		gbc_jwtSignatureButton.insets = new Insets(0, 0, 5, 5);
		gbc_jwtSignatureButton.gridx = 1;
		gbc_jwtSignatureButton.gridy = 6;
		add(jwtSignatureButton, gbc_jwtSignatureButton);

		GridBagConstraints gbc_jwtOuputField = new GridBagConstraints();
		gbc_jwtOuputField.insets = new Insets(0, 0, 5, 5);
		gbc_jwtOuputField.fill = GridBagConstraints.BOTH;
		gbc_jwtOuputField.gridx = 1;
		gbc_jwtOuputField.gridy = 9;

		JTextComponent.removeKeymap("RTextAreaKeymap");
		jwtOuputField = rSyntaxTextAreaFactory.rSyntaxTextArea();
		UIManager.put("RSyntaxTextAreaUI.actionMap", null);
		UIManager.put("RSyntaxTextAreaUI.inputMap", null);
		UIManager.put("RTextAreaUI.actionMap", null);
		UIManager.put("RTextAreaUI.inputMap", null);
		jwtOuputField.setWhitespaceVisible(true);

		SyntaxScheme scheme = jwtOuputField.getSyntaxScheme();
		Style style = new Style();
		style.foreground = new Color(222, 133, 10);
		scheme.setStyle(Token.LITERAL_STRING_DOUBLE_QUOTE, style);
		jwtOuputField.revalidate();
		jwtOuputField.setHighlightCurrentLine(false);
		jwtOuputField.setCurrentLineHighlightColor(Color.WHITE);
		jwtOuputField.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_JAVASCRIPT);
		jwtOuputField.setEditable(false);
		// no context menu on right-click
		jwtOuputField.setPopupMenu(new JPopupMenu());

		// hopefully fixing:
		// java.lang.ClassCastException: class
		// javax.swing.plaf.nimbus.DerivedColor$UIResource cannot be cast to class
		// java.lang.Boolean (javax.swing.plaf.nimbus.DerivedColor$UIResource is in
		// module java.desktop of loader 'bootstrap';
		// java.lang.Boolean is in module java.base of loader 'bootstrap')
		SwingUtilities.invokeLater(() -> {
			RTextScrollPane sp = new RTextScrollPane(jwtOuputField);
			sp.setLineNumbersEnabled(false);
			add(sp, gbc_jwtOuputField);
		});

		lblExtendedVerificationInfo = new JLabel("");
		GridBagConstraints gbc_lblExtendedVerificationInfo = new GridBagConstraints();
		gbc_lblExtendedVerificationInfo.insets = new Insets(0, 0, 5, 5);
		gbc_lblExtendedVerificationInfo.gridx = 1;
		gbc_lblExtendedVerificationInfo.gridy = 7;
		add(lblExtendedVerificationInfo, gbc_lblExtendedVerificationInfo);

		lblDecodedJwt = new JLabel(Strings.DECODED_JWT);
		lblDecodedJwt.setFont(currentFont);
		GridBagConstraints gbc_lblDecodedJwt = new GridBagConstraints();
		gbc_lblDecodedJwt.anchor = GridBagConstraints.WEST;
		gbc_lblDecodedJwt.insets = new Insets(0, 0, 5, 5);
		gbc_lblDecodedJwt.gridx = 1;
		gbc_lblDecodedJwt.gridy = 8;
		add(lblDecodedJwt, gbc_lblDecodedJwt);

		
		lbRegisteredClaims = new JLabel();
		lbRegisteredClaims.putClientProperty("html.disable", false);
		lbRegisteredClaims.setBackground(new Color(238, 238, 238));
		GridBagConstraints gbc_lbRegisteredClaims = new GridBagConstraints();
		gbc_lbRegisteredClaims.fill = GridBagConstraints.BOTH;
		gbc_lbRegisteredClaims.insets = new Insets(0, 0, 5, 5);
		gbc_lbRegisteredClaims.gridx = 1;
		gbc_lbRegisteredClaims.gridy = 11;
		add(lbRegisteredClaims, gbc_lbRegisteredClaims);
	}


	public String getJWTInput() {
		return jwtInputField.getText();
	}

	public String getKeyInput() {
		return jwtKeyArea.getText();
	}
}

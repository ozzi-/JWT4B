package gui;

import java.awt.Color;
import java.awt.Dimension;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.GridLayout;
import java.awt.SystemColor;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionListener;
import java.awt.event.KeyListener;
import java.util.Enumeration;

import javax.swing.AbstractButton;
import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JRadioButton;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.ScrollPaneConstants;
import javax.swing.SwingConstants;
import javax.swing.SwingUtilities;
import javax.swing.UIManager;
import javax.swing.event.DocumentListener;
import javax.swing.text.JTextComponent;

import org.fife.ui.rsyntaxtextarea.RSyntaxTextArea;
import org.fife.ui.rsyntaxtextarea.Style;
import org.fife.ui.rsyntaxtextarea.SyntaxConstants;
import org.fife.ui.rsyntaxtextarea.SyntaxScheme;
import org.fife.ui.rsyntaxtextarea.Token;
import org.fife.ui.rsyntaxtextarea.TokenTypes;
import org.fife.ui.rtextarea.RTextScrollPane;

import app.controllers.ReadableTokenFormat;
import app.helpers.Config;
import app.helpers.Output;
import model.JWTInterceptModel;
import model.Strings;

public class JWTInterceptTab extends JPanel {

	private static final long serialVersionUID = 1L;
	private static final String HTML_DISABLE = "html.disable";
	private final JWTInterceptModel jwtIM;
	private final RSyntaxTextAreaFactory rSyntaxTextAreaFactory;
	private JRadioButton rdbtnRecalculateSignature;
	private JRadioButton rdbtnRandomKey;
	private JRadioButton rdbtnOriginalSignature;
	private JRadioButton rdbtnChooseSignature;

	private JTextArea jwtKeyArea;

	private RSyntaxTextArea jwtHeaderArea;
	private RSyntaxTextArea jwtPayloadArea;
	private RSyntaxTextArea jwtSignatureArea;

	private JLabel lblSecretKey;
	private JRadioButton rdbtnDontModifySignature;
	private JLabel lblProblem;
	private JComboBox<String> noneAttackComboBox;
	private JLabel lblNewLabel;
	private JLabel lblCookieFlags;
	private JLabel lbRegisteredClaims;
	private JCheckBox chkbxCVEAttack;
	private JButton btnCopyPubPrivKeyCVEAttack;
	private ButtonGroup btgrp;

	public JWTInterceptTab(JWTInterceptModel jwtIM, RSyntaxTextAreaFactory rSyntaxTextAreaFactory) {
		this.jwtIM = jwtIM;
		this.rSyntaxTextAreaFactory = rSyntaxTextAreaFactory;
		drawGui();
	}

	public void registerActionListeners(ActionListener dontMofiy, ActionListener randomKeyListener, ActionListener originalSignatureListener, ActionListener recalculateSignatureListener,
			ActionListener chooseSignatureListener, ActionListener algAttackListener, ActionListener cveAttackListener, DocumentListener syncKey, KeyListener jwtAreaTyped) {
		rdbtnDontModifySignature.addActionListener(dontMofiy);
		rdbtnRecalculateSignature.addActionListener(randomKeyListener);
		rdbtnOriginalSignature.addActionListener(originalSignatureListener);
		rdbtnChooseSignature.addActionListener(chooseSignatureListener);
		rdbtnRandomKey.addActionListener(recalculateSignatureListener);
		noneAttackComboBox.addActionListener(algAttackListener);
		chkbxCVEAttack.addActionListener(cveAttackListener);
		jwtKeyArea.getDocument().addDocumentListener(syncKey);
		jwtHeaderArea.addKeyListener(jwtAreaTyped);
		jwtPayloadArea.addKeyListener(jwtAreaTyped);
	}

	private void drawGui() {
		setLayout(new GridLayout(1, 2, 10, 0));

		JPanel areasPanel = new JPanel();
		areasPanel.setLayout(new GridLayout(3, 1));

		JPanel actionPanel = new JPanel();
		actionPanel.setLayout(new GridBagLayout());
		GridBagConstraints c = new GridBagConstraints();
		c.gridx = 0;
		c.gridy = 0;
		c.anchor = GridBagConstraints.NORTHWEST;

		fixSyntaxArea();

		jwtHeaderArea = rSyntaxTextAreaFactory.rSyntaxTextArea(3, 20);
		jwtHeaderArea.setMarginLinePosition(70);
		jwtHeaderArea.setWhitespaceVisible(true);
		SyntaxScheme scheme = jwtHeaderArea.getSyntaxScheme();
		Style style = new Style();
		style.foreground = new Color(222, 133, 10);
		scheme.setStyle(Token.LITERAL_STRING_DOUBLE_QUOTE, style);
		jwtHeaderArea.revalidate();
		jwtHeaderArea.setHighlightCurrentLine(false);
		jwtHeaderArea.setCurrentLineHighlightColor(Color.WHITE);
		jwtHeaderArea.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_JAVASCRIPT);
		jwtHeaderArea.setEditable(true);
		jwtHeaderArea.setPopupMenu(new JPopupMenu());
		RTextScrollPane headerPane = new RTextScrollPane(jwtHeaderArea);
		headerPane.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED);
		headerPane.setLineNumbersEnabled(false);

		jwtPayloadArea = rSyntaxTextAreaFactory.rSyntaxTextArea(3, 20);
		jwtPayloadArea.setMarginLinePosition(70);
		jwtPayloadArea.setWhitespaceVisible(true);
		scheme = jwtPayloadArea.getSyntaxScheme();
		style = new Style();
		style.foreground = new Color(222, 133, 10);
		scheme.setStyle(TokenTypes.LITERAL_STRING_DOUBLE_QUOTE, style);
		jwtPayloadArea.revalidate();
		jwtPayloadArea.setHighlightCurrentLine(false);
		jwtPayloadArea.setCurrentLineHighlightColor(Color.WHITE);
		jwtPayloadArea.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_JAVASCRIPT);
		jwtPayloadArea.setEditable(true);
		jwtPayloadArea.setPopupMenu(new JPopupMenu());
		RTextScrollPane payloadPane = new RTextScrollPane(jwtPayloadArea);
		payloadPane.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED);
		payloadPane.setLineNumbersEnabled(false);

		jwtSignatureArea = rSyntaxTextAreaFactory.rSyntaxTextArea(3, 10);
		jwtSignatureArea.setMarginLinePosition(70);
		jwtSignatureArea.setLineWrap(true);
		jwtSignatureArea.setWhitespaceVisible(true);
		scheme = jwtSignatureArea.getSyntaxScheme();
		style = new Style();
		style.foreground = new Color(222, 133, 10);
		scheme.setStyle(TokenTypes.LITERAL_STRING_DOUBLE_QUOTE, style);
		jwtSignatureArea.revalidate();
		jwtSignatureArea.setHighlightCurrentLine(false);
		jwtSignatureArea.setCurrentLineHighlightColor(Color.WHITE);
		jwtSignatureArea.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_NONE);
		jwtSignatureArea.setEditable(true);
		jwtSignatureArea.setPopupMenu(new JPopupMenu());
		RTextScrollPane signaturePane = new RTextScrollPane(jwtSignatureArea);
		signaturePane.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED);
		signaturePane.setLineNumbersEnabled(false);

		areasPanel.add(headerPane);
		areasPanel.add(payloadPane);
		areasPanel.add(signaturePane);

		rdbtnDontModifySignature = new JRadioButton(Strings.DONT_MODIFY);
		rdbtnDontModifySignature.setToolTipText(Strings.DONT_MODIFY_TT);
		rdbtnDontModifySignature.setSelected(true);
		rdbtnDontModifySignature.setHorizontalAlignment(SwingConstants.LEFT);
		c.gridy = 1;
		actionPanel.add(rdbtnDontModifySignature, c);

		rdbtnRecalculateSignature = new JRadioButton(Strings.RECALC_SIGNATURE);
		rdbtnRecalculateSignature.putClientProperty(HTML_DISABLE, null);
		rdbtnRecalculateSignature.setToolTipText(Strings.RECALC_SIG_TT);
		rdbtnRecalculateSignature.setHorizontalAlignment(SwingConstants.LEFT);
		c.gridy = 2;
		actionPanel.add(rdbtnRecalculateSignature, c);

		rdbtnOriginalSignature = new JRadioButton(Strings.KEEP_ORIG_SIG);
		rdbtnOriginalSignature.setToolTipText(Strings.KEEP_ORIG_SIG_TT);
		rdbtnOriginalSignature.setHorizontalAlignment(SwingConstants.LEFT);
		c.gridy = 3;
		actionPanel.add(rdbtnOriginalSignature, c);

		rdbtnRandomKey = new JRadioButton(Strings.RANDOM_KEY);
		rdbtnRandomKey.putClientProperty(HTML_DISABLE, null);
		rdbtnRandomKey.setToolTipText(Strings.RANDOM_KEY_TT);
		rdbtnRandomKey.setHorizontalAlignment(SwingConstants.LEFT);
		c.gridy = 4;
		actionPanel.add(rdbtnRandomKey, c);

		rdbtnChooseSignature = new JRadioButton(Strings.CHOOSE_SIG);
		rdbtnChooseSignature.setToolTipText(Strings.CHOOSE_SIG_TT);
		rdbtnChooseSignature.setHorizontalAlignment(SwingConstants.LEFT);
		c.gridy = 5;
		actionPanel.add(rdbtnChooseSignature, c);

		lblSecretKey = new JLabel(Strings.RECALC_KEY_INTERCEPT);
		c.gridy = 6;
		actionPanel.add(lblSecretKey, c);

		jwtKeyArea = new JTextArea("");
		jwtKeyArea.setRows(3);
		jwtKeyArea.setLineWrap(false);
		jwtKeyArea.setEnabled(false);
		jwtKeyArea.setPreferredSize(new Dimension(350, 55));

		JScrollPane jp = new JScrollPane(jwtKeyArea);
		c.gridy = 7;
		c.weightx = 0.9;
		jp.setMinimumSize(new Dimension(350, 55));
		actionPanel.add(jp, c);

		lblProblem = new JLabel("");
		lblProblem.setForeground(Color.RED);
		c.gridy = 8;
		actionPanel.add(lblProblem, c);

		lblNewLabel = new JLabel("Alg None Attack:");
		c.gridy = 9;
		actionPanel.add(lblNewLabel, c);

		noneAttackComboBox = new JComboBox<>();
		noneAttackComboBox.setMaximumSize(new Dimension(300, 20));
		noneAttackComboBox.setPreferredSize(new Dimension(300, 20));
		c.gridy = 10;
		actionPanel.add(noneAttackComboBox, c);

		chkbxCVEAttack = new JCheckBox("CVE-2018-0114 Attack");
		chkbxCVEAttack.setToolTipText("The public and private key used can be found in src/app/helpers/Strings.java");
		chkbxCVEAttack.setHorizontalAlignment(SwingConstants.LEFT);
		c.gridy = 11;
		actionPanel.add(chkbxCVEAttack, c);

		lblCookieFlags = new JLabel("");
		lblCookieFlags.putClientProperty(HTML_DISABLE, null);
		c.gridy = 12;
		actionPanel.add(lblCookieFlags, c);

		lbRegisteredClaims = new JLabel();
		lbRegisteredClaims.putClientProperty(HTML_DISABLE, null);
		lbRegisteredClaims.setBackground(SystemColor.controlHighlight);
		c.gridy = 13;
		actionPanel.add(lbRegisteredClaims, c);

		btnCopyPubPrivKeyCVEAttack = new JButton("Copy used public & private\r\nkey to clipboard used in CVE attack");
		btnCopyPubPrivKeyCVEAttack.setVisible(false);
		c.gridy = 14;
		actionPanel.add(btnCopyPubPrivKeyCVEAttack, c);

		add(areasPanel);
		add(actionPanel);

		setVisible(true);

		btgrp = new ButtonGroup();
		btgrp.add(rdbtnDontModifySignature);
		btgrp.add(rdbtnOriginalSignature);
		btgrp.add(rdbtnRandomKey);
		btgrp.add(rdbtnRecalculateSignature);
		btgrp.add(rdbtnChooseSignature);

		btnCopyPubPrivKeyCVEAttack.addActionListener(a -> Toolkit.getDefaultToolkit().getSystemClipboard()
				.setContents(new StringSelection("Public Key:\r\n" + Config.cveAttackModePublicKey + "\r\n\r\nPrivate Key:\r\n" + Config.cveAttackModePrivateKey), null));

		noneAttackComboBox.addItem("  -");
		noneAttackComboBox.addItem("Alg: none");
		noneAttackComboBox.addItem("Alg: None");
		noneAttackComboBox.addItem("Alg: nOnE");
		noneAttackComboBox.addItem("Alg: NONE");

	}

	private void fixSyntaxArea() {
		JTextComponent.removeKeymap("RTextAreaKeymap");
		UIManager.put("RSyntaxTextAreaUI.actionMap", null);
		UIManager.put("RSyntaxTextAreaUI.inputMap", null);
		UIManager.put("RTextAreaUI.actionMap", null);
		UIManager.put("RTextAreaUI.inputMap", null);
	}

	public void setProblemLbl(String txt) {
		lblProblem.setText(txt);
	}

	public void setRadiosState(boolean enabled) {
		Enumeration<AbstractButton> buttons = btgrp.getElements();
		while (buttons.hasMoreElements()) {
			buttons.nextElement().setEnabled(enabled);
		}
	}

	public AbstractButton getRdbtnDontModify() {
		return rdbtnDontModifySignature;
	}

	public JRadioButton getRdbtnChooseSignature() {
		return rdbtnChooseSignature;
	}

	public JRadioButton getRdbtnRecalculateSignature() {
		return rdbtnRecalculateSignature;
	}

	public JComboBox<String> getNoneAttackComboBox() {
		return noneAttackComboBox;
	}

	public JCheckBox getCVEAttackCheckBox() {
		return chkbxCVEAttack;
	}

	public JRadioButton getRdbtnRandomKey() {
		return rdbtnRandomKey;
	}

	public JButton getCVECopyBtn() {
		return btnCopyPubPrivKeyCVEAttack;
	}

	public JRadioButton getRdbtnOriginalSignature() {
		return rdbtnOriginalSignature;
	}

	public void updateSetView(final boolean reset) {
		updateSetView(reset, false);
	}

	public void updateSetView(final boolean reset, final boolean noKeyUpdate) {
		SwingUtilities.invokeLater(() -> {
			Output.output("Updating view - reset: " + reset);

			if (reset) {
				rdbtnDontModifySignature.setSelected(true);
				jwtKeyArea.setText("");
				jwtKeyArea.setEnabled(false);
			} else {
				jwtHeaderArea.setText(ReadableTokenFormat.jsonBeautify(jwtIM.getJwToken().getHeaderJson()));
				jwtPayloadArea.setText(ReadableTokenFormat.jsonBeautify(jwtIM.getJwToken().getPayloadJson()));
				jwtSignatureArea.setText(jwtIM.getJwToken().getSignature());
				if (noKeyUpdate) {
					jwtKeyArea.setText(jwtIM.getJWTKey());
				}
			}
			lblProblem.setText(jwtIM.getProblemDetail());
			// -> response of https://oz-web.com/jwt/request_cookie.php
			if (jwtIM.getcFW().isCookie()) {
				lblCookieFlags.setText(jwtIM.getcFW().toHTMLString());
			} else {
				lblCookieFlags.setText("");
			}
			lbRegisteredClaims.setText(jwtIM.getTimeClaimsAsText());
		});
	}

	public RSyntaxTextArea getJwtHeaderArea() {
		return jwtHeaderArea;
	}

	public RSyntaxTextArea getJwtPayloadArea() {
		return jwtPayloadArea;
	}

	public RSyntaxTextArea getJwtSignatureArea() {
		return jwtSignatureArea;
	}

	public void setKeyFieldState(boolean state) {
		jwtKeyArea.setEnabled(state);
	}

	public String getSelectedData() {
		return jwtPayloadArea.getSelectedText();
	}

	public String getKeyFieldValue() {
		return jwtKeyArea.getText();
	}

	public JTextArea getKeyField() {
		return jwtKeyArea;
	}

	public void setKeyFieldValue(String string) {
		jwtKeyArea.setText(string);
	}

}

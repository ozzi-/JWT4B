package gui;

import java.awt.Color;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.GridLayout;
import java.awt.SystemColor;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyListener;
import java.util.ArrayList;

import javax.swing.AbstractButton;
import javax.swing.BoxLayout;
import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JRadioButton;
import javax.swing.JScrollPane;
import javax.swing.JSeparator;
import javax.swing.JTextArea;
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
import org.fife.ui.rtextarea.RTextScrollPane;

import app.controllers.ReadableTokenFormat;
import app.helpers.Config;
import app.helpers.Output;
import model.JWTInterceptModel;
import model.Strings;
import javax.swing.ScrollPaneConstants;

public class JWTInterceptTab extends JPanel {

	private static final long serialVersionUID = 1L;
	private JWTInterceptModel jwtIM;
	private String jwtAreaOriginalContent = "none";
	private JRadioButton rdbtnRecalculateSignature;
	private JRadioButton rdbtnRandomKey;
	private JRadioButton rdbtnOriginalSignature;
	private JRadioButton rdbtnChooseSignature;

	private JTextArea jwtKeyArea;

	private RSyntaxTextArea jwtHeaderArea;
	private RSyntaxTextArea jwtPayloadArea;
	private RSyntaxTextArea jwtSignatureArea;

	private JLabel lblSecretKey;
	private JSeparator separator;
	private JRadioButton rdbtnDontModifySignature;
	private JLabel lblProblem;
	private JComboBox<String> noneAttackComboBox;
	private JLabel lblNewLabel;
	private JLabel lblCookieFlags;
	private JLabel lbRegisteredClaims;
	private JCheckBox chkbxCVEAttack;
	private JButton btnCopyPubPrivKeyCVEAttack;

	public JWTInterceptTab(JWTInterceptModel jwtIM) {
		this.jwtIM = jwtIM;
		drawGui();
	}
	
	public void registerActionListeners(ActionListener dontMofiy,
      ActionListener randomKeyListener,
      ActionListener originalSignatureListener,
      ActionListener recalculateSignatureListener,
      ActionListener chooseSignatureListener,
      ActionListener algAttackListener,
      ActionListener cveAttackListener,
      DocumentListener syncKey,
      KeyListener jwtAreaTyped){
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

		setLayout(new GridLayout(1, 2,5,5));
		JPanel areasPanel = new JPanel();
		JPanel actionPanel = new JPanel();

		areasPanel.setLayout(new GridLayout(4,1));

		fixSyntaxArea();

		jwtHeaderArea = new RSyntaxTextArea(10,20);
		jwtHeaderArea.setMarginLinePosition(70);
		jwtHeaderArea.setWhitespaceVisible(true);
		SyntaxScheme scheme = jwtHeaderArea.getSyntaxScheme();
		Style style = new Style();
		style.foreground = new Color(222,133,10);
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


		jwtPayloadArea = new RSyntaxTextArea(10,20);
		jwtPayloadArea.setMarginLinePosition(70);
		jwtPayloadArea.setWhitespaceVisible(true);
		//area.setMinimumSize(new Dimension(300, 300));
		scheme = jwtPayloadArea.getSyntaxScheme();
		style = new Style();
		style.foreground = new Color(222,133,10);
		scheme.setStyle(Token.LITERAL_STRING_DOUBLE_QUOTE, style);
		jwtPayloadArea.revalidate();
		jwtPayloadArea.setHighlightCurrentLine(false);
		jwtPayloadArea.setCurrentLineHighlightColor(Color.WHITE);
		jwtPayloadArea.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_JAVASCRIPT);
		jwtPayloadArea.setEditable(true);
		jwtPayloadArea.setPopupMenu(new JPopupMenu());
		RTextScrollPane payloadPane = new RTextScrollPane(jwtPayloadArea);
		payloadPane.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED);
		payloadPane.setLineNumbersEnabled(false);

		jwtSignatureArea = new RSyntaxTextArea(10,10);
		jwtSignatureArea.setMarginLinePosition(70);
		jwtSignatureArea.setLineWrap(true);
		jwtSignatureArea.setWhitespaceVisible(true);
		//area.setMinimumSize(new Dimension(300, 300));
		scheme = jwtSignatureArea.getSyntaxScheme();
		style = new Style();
		style.foreground = new Color(222,133,10);
		scheme.setStyle(Token.LITERAL_STRING_DOUBLE_QUOTE, style);
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


		actionPanel.setLayout(new GridLayout(14,1));

		rdbtnDontModifySignature = new JRadioButton(Strings.dontModify);
		rdbtnDontModifySignature.setToolTipText(Strings.dontModifyToolTip);
		rdbtnDontModifySignature.setSelected(true);
		rdbtnDontModifySignature.setHorizontalAlignment(SwingConstants.LEFT);
		actionPanel.add(rdbtnDontModifySignature);

		rdbtnRecalculateSignature = new JRadioButton(Strings.recalculateSignature);
		rdbtnRecalculateSignature.setToolTipText(Strings.recalculateSignatureToolTip);
		rdbtnRecalculateSignature.setHorizontalAlignment(SwingConstants.LEFT);
		actionPanel.add(rdbtnRecalculateSignature);

		rdbtnOriginalSignature = new JRadioButton(Strings.keepOriginalSignature);
		rdbtnOriginalSignature.setToolTipText(Strings.keepOriginalSignatureToolTip);
		rdbtnOriginalSignature.setHorizontalAlignment(SwingConstants.LEFT);
		actionPanel.add(rdbtnOriginalSignature);

		rdbtnRandomKey = new JRadioButton(Strings.randomKey);
		rdbtnRandomKey.setToolTipText(Strings.randomKeyToolTip);
		rdbtnRandomKey.setHorizontalAlignment(SwingConstants.LEFT);
		actionPanel.add(rdbtnRandomKey);

		rdbtnChooseSignature = new JRadioButton(Strings.chooseSignature);
		rdbtnChooseSignature.setToolTipText(Strings.chooseSignatureToolTip);
		rdbtnChooseSignature.setHorizontalAlignment(SwingConstants.LEFT);
		actionPanel.add(rdbtnChooseSignature);

		lblSecretKey = new JLabel(Strings.interceptRecalculationKey);
		actionPanel.add(lblSecretKey);

		jwtKeyArea = new JTextArea("");
		jwtKeyArea.setRows(2);
		jwtKeyArea.setLineWrap(false);
		jwtKeyArea.setEnabled(false);

		JScrollPane jp = new JScrollPane(jwtKeyArea);
		jp.setMinimumSize(new Dimension(100, 70));
		actionPanel.add(jp);

		lblProblem = new JLabel("");
		lblProblem.setForeground(Color.RED);
		actionPanel.add(lblProblem);


		JPanel algAttackPanel = new JPanel();
		//algAttackPanel.setLayout(new BoxLayout(algAttackPanel, BoxLayout.PAGE_AXIS));
		algAttackPanel.setLayout(new FlowLayout());

		lblCookieFlags = new JLabel("");
		actionPanel.add(lblCookieFlags);

		lblNewLabel = new JLabel("Alg None Attack:");
		algAttackPanel.add(lblNewLabel);
		actionPanel.add(algAttackPanel);

		noneAttackComboBox = new JComboBox<>();
		noneAttackComboBox.setMaximumSize(new Dimension(100,50));
		noneAttackComboBox.setPreferredSize(new Dimension(100,50));
		actionPanel.add(noneAttackComboBox);

		chkbxCVEAttack = new JCheckBox("CVE-2018-0114 Attack");
		chkbxCVEAttack.setToolTipText("The public and private key used can be found in src/app/helpers/Strings.java");
		chkbxCVEAttack.setHorizontalAlignment(SwingConstants.LEFT);
		actionPanel.add(chkbxCVEAttack);

		lbRegisteredClaims = new JLabel();
		lbRegisteredClaims.setBackground(SystemColor.controlHighlight);
		actionPanel.add(lbRegisteredClaims);

		btnCopyPubPrivKeyCVEAttack = new JButton("Copy used public & private\r\nkey to clipboard used in CVE attack");
		btnCopyPubPrivKeyCVEAttack.setVisible(false);
		actionPanel.add(btnCopyPubPrivKeyCVEAttack);

		add(areasPanel);
		add(actionPanel);

		setVisible(true);

		ButtonGroup btgrp = new ButtonGroup();
		btgrp.add(rdbtnDontModifySignature);
		btgrp.add(rdbtnOriginalSignature);
		btgrp.add(rdbtnRandomKey);
		btgrp.add(rdbtnRecalculateSignature);
		btgrp.add(rdbtnChooseSignature);


		btnCopyPubPrivKeyCVEAttack.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				Toolkit.getDefaultToolkit()
		        .getSystemClipboard()
		        .setContents(
		                new StringSelection("Public Key:\r\n"+Config.cveAttackModePublicKey+"\r\n\r\nPrivate Key:\r\n"+Config.cveAttackModePrivateKey),
		                null
		        );
			}
		});

		
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

	public void setProblemLbl(String txt){
		lblProblem.setText(txt);
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

	public JButton getCVECopyBtn(){
		return btnCopyPubPrivKeyCVEAttack;
	}
	
	public JRadioButton getRdbtnOriginalSignature() {
		return rdbtnOriginalSignature;
	}

	public void updateSetView(final boolean reset) {
		updateSetView(reset,false);
	}
	public void updateSetView(final boolean reset, final boolean noKeyUpdate) {
		SwingUtilities.invokeLater(new Runnable() {
			public void run() {
				Output.output("Updating view - reset: "+reset);

				if(reset){
					rdbtnDontModifySignature.setSelected(true);
					jwtKeyArea.setText("");
					jwtKeyArea.setEnabled(false);
				}else{
					// jwtArea.setText(ReadableTokenFormat.getReadableFormat(jwtIM.getJwToken()));
					jwtHeaderArea.setText(ReadableTokenFormat.jsonBeautify(jwtIM.getJwToken().getHeaderJson()));
					jwtPayloadArea.setText(ReadableTokenFormat.jsonBeautify(jwtIM.getJwToken().getPayloadJson()));
					jwtSignatureArea.setText(jwtIM.getJwToken().getSignature());
					if(noKeyUpdate){
						jwtKeyArea.setText(jwtIM.getJWTKey());
					}
				}

				// TODO where to reset caret? ? jwtArea.setCaretPosition(0);
				lblProblem.setText(jwtIM.getProblemDetail());
				// TODO are cookie flag wrappers displayed?
				if(jwtIM.getcFW().isCookie()){
					lblCookieFlags.setText(jwtIM.getcFW().toHTMLString());
				}else{
					lblCookieFlags.setText("");
				}
				lbRegisteredClaims.setText(jwtIM.getTimeClaimsAsText());
			}
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

	public void setKeyFieldState(boolean state){
		jwtKeyArea.setEnabled(state);
	}
	
	public boolean jwtWasChanged() {
		// TODO do for all three!
		if(jwtHeaderArea.getText()==null) {
			return false;
		}
		// TODO fix this for all three
		return !jwtAreaOriginalContent.equals(jwtHeaderArea.getText());
	}
	
	public ArrayList<String> getJWTfromArea(){
		ArrayList<String> parts = new ArrayList<>();
		parts.add(jwtHeaderArea.getText());
		parts.add(jwtPayloadArea.getText());
		parts.add(jwtSignatureArea.getText());
		return parts;
	}

	public String getSelectedData() {
		// TODO what to return now that it is three areas?
		return jwtPayloadArea.getSelectedText();
	}

	public String getKeyFieldValue() {
		return jwtKeyArea.getText();
	}
	
	public void setKeyFieldValue(String string) {
		jwtKeyArea.setText(string);
	}

  public JComboBox<String> getAlgorithmComboBox() {
		return noneAttackComboBox;
  }

}
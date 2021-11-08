package gui;

import java.awt.Color;
import java.awt.Dimension;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.SystemColor;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.*;
import javax.swing.event.ChangeListener;
import javax.swing.event.DocumentListener;
import javax.swing.text.AbstractDocument;
import javax.swing.text.Document;
import javax.swing.text.JTextComponent;

import app.algorithm.AlgorithmLinker;
import app.algorithm.AlgorithmWrapper;
import app.controllers.JWTInterceptTabController;
import app.controllers.ReadableTokenFormat;
import app.helpers.Output;
import model.CustomJWToken;
import org.fife.ui.rsyntaxtextarea.RSyntaxTextArea;
import org.fife.ui.rsyntaxtextarea.Style;
import org.fife.ui.rsyntaxtextarea.SyntaxConstants;
import org.fife.ui.rsyntaxtextarea.SyntaxScheme;
import org.fife.ui.rsyntaxtextarea.Token;
import org.fife.ui.rtextarea.RTextScrollPane;

import app.helpers.Config;
import model.JWTInterceptModel;
import model.Strings;

public class JWTInterceptTab extends JPanel {

	private static final long serialVersionUID = 1L;
	private JWTInterceptModel jwtIM;

	private RSyntaxTextArea jwtArea;

	private JLabel algorithmLabel;
	private JComboBox<String> algorithmComboBox;

	private JButton createKeyButton;
	private JButton loadKeyButton;

	private JLabel lblSecretKey;
	private JSeparator separator;
	private JTextArea jwtKeyArea;

	private JButton updateSignatureButton;

	private JLabel lblProblem;
	private JLabel lblCookieFlags;
	private JLabel lbRegisteredClaims;

	private JCheckBox chkbxCVEAttack;
	private JButton btnCopyPubPrivKeyCVEAttack;

	public JWTInterceptTab(JWTInterceptModel jwtIM) {
		this.jwtIM = jwtIM;
		drawGui();
	}
	
	public void registerActionListeners(
			ActionListener changeAlgorithmListener,
			ActionListener createKeyListener,
			ActionListener updateSignatureListener,
			DocumentListener jwtChangedListener,
			DocumentListener keyChangedListener) {
		algorithmComboBox.addActionListener(changeAlgorithmListener);
		createKeyButton.addActionListener(createKeyListener);
		updateSignatureButton.addActionListener(updateSignatureListener);

		// listen for changes to text in JWT and Key TextAreas
		jwtArea.getDocument().addDocumentListener(jwtChangedListener);
		jwtKeyArea.getDocument().addDocumentListener(keyChangedListener);
	}
	
	private void drawGui() {
		GridBagLayout gridBagLayout = new GridBagLayout();
		gridBagLayout.columnWidths = new int[] {0, 250, 0, 0, 0};
		gridBagLayout.rowHeights = new int[]{10, 0, 0, 0, 0, 0, 0, 30, 0, 0, 0, 0, 0, 0, 0};
		gridBagLayout.columnWeights = new double[]{0.0, 1.0, 0.01, 0.01};
		gridBagLayout.rowWeights = new double[]{0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 1.0, Double.MIN_VALUE};
		setLayout(gridBagLayout);

		JTextComponent.removeKeymap("RTextAreaKeymap");
		jwtArea = new RSyntaxTextArea(20,100);
		//jwtArea.setBorder(BorderFactory.createLineBorder(Color.BLACK));
		UIManager.put("RSyntaxTextAreaUI.actionMap", null);
		UIManager.put("RSyntaxTextAreaUI.inputMap", null);
		UIManager.put("RTextAreaUI.actionMap", null);
		UIManager.put("RTextAreaUI.inputMap", null);
		jwtArea.setMarginLinePosition(70);
		jwtArea.setWhitespaceVisible(true);

		jwtArea.setMinimumSize(new Dimension(300, 300));
		SyntaxScheme scheme = jwtArea.getSyntaxScheme();
		Style style = new Style();
		style.foreground = new Color(222,133,10);
		scheme.setStyle(Token.LITERAL_STRING_DOUBLE_QUOTE, style);
		jwtArea.revalidate();
		jwtArea.setHighlightCurrentLine(false);
		jwtArea.setCurrentLineHighlightColor(Color.WHITE);
		jwtArea.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_JAVASCRIPT);
		jwtArea.setEditable(true);
		jwtArea.setPopupMenu(new JPopupMenu());
		RTextScrollPane sp = new RTextScrollPane(jwtArea);
		sp.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED);
		sp.setLineNumbersEnabled(false);

		GridBagConstraints gbcLeft = new GridBagConstraints();
		gbcLeft.insets = new Insets(5, 5, 5, 5);
		gbcLeft.fill = GridBagConstraints.BOTH;
		gbcLeft.gridheight = 12;
		gbcLeft.gridwidth = 1;
		gbcLeft.gridx = 1;
		gbcLeft.gridy = 1;
		add(sp, gbcLeft);

		// Algorithm Dropdown
		algorithmLabel = new JLabel("Algorithm:");
		GridBagConstraints gbcRight = new GridBagConstraints();
		gbcRight.insets = new Insets(5, 5, 5, 5);
		gbcRight.anchor = GridBagConstraints.WEST;
		gbcRight.gridx = 2;
		gbcRight.gridy = 1;
		gbcRight.gridheight = 1;
		add(algorithmLabel, gbcRight);

		algorithmComboBox = new JComboBox<String>();
		for(final AlgorithmWrapper alg: AlgorithmLinker.getSupportedAlgorithms()){
			algorithmComboBox.addItem(alg.getAlgorithm());
		}
		//		algorithmComboBox.setToolTipText("TODO");
		//algorithmComboBox.setHorizontalAlignment(SwingConstants.LEFT);
		//GridBagConstraints gbc_noneAttackComboBox = new GridBagConstraints();
		gbcRight.gridx = 3;
		gbcRight.gridy = 1;
		gbcRight.anchor = GridBagConstraints.EAST;
		add(algorithmComboBox, gbcRight);


		separator = new JSeparator(SwingConstants.HORIZONTAL);
		separator.setPreferredSize(new Dimension(100, 1));
		GridBagConstraints gbcSeparators = new GridBagConstraints();
		gbcSeparators.insets = new Insets(5, 5, 5, 5);
		gbcSeparators.fill = GridBagConstraints.BOTH;
		gbcSeparators.gridx = 2;
		gbcSeparators.gridy = 2;
		//gbcSeparators.weighty = 0.1;
		gbcSeparators.gridwidth = 2;
		add(separator, gbcSeparators);

		lblSecretKey = new JLabel(Strings.keyTextBoxHeader);
		gbcRight.gridx = 2;
		gbcRight.gridy = 3;
		gbcRight.gridwidth = 2;
		gbcRight.anchor = GridBagConstraints.WEST;
		add(lblSecretKey, gbcRight);

		createKeyButton = new JButton(Strings.createKey);
		createKeyButton.setVisible(true);
		createKeyButton.setHorizontalAlignment(SwingConstants.LEFT);
		gbcRight.anchor = GridBagConstraints.WEST;
		gbcRight.gridx = 2;
		gbcRight.gridy = 4;
		gbcRight.gridwidth = 1;
		add(createKeyButton, gbcRight);

		loadKeyButton = new JButton(Strings.loadKey);
		loadKeyButton.setVisible(true);
		// TODO: reenable
		loadKeyButton.setEnabled(false);
		loadKeyButton.setHorizontalAlignment(SwingConstants.LEFT);
		gbcRight.anchor = GridBagConstraints.EAST;
		gbcRight.gridx = 3;
		gbcRight.gridy = 4;
		add(loadKeyButton, gbcRight);


		jwtKeyArea = new JTextArea("");
		jwtKeyArea.setToolTipText(Strings.keyTextBoxToolTip);
		jwtKeyArea.setRows(2);
		jwtKeyArea.setLineWrap(false);
		jwtKeyArea.setEditable(true);
		jwtKeyArea.setEnabled(true);
		JScrollPane jp = new JScrollPane(jwtKeyArea);
		jp.setMinimumSize(new Dimension(50, 50));
		gbcRight.anchor = GridBagConstraints.WEST;
		gbcRight.gridwidth = 2;
		gbcRight.gridx = 2;
		gbcRight.gridy = 6;
		gbcRight.fill = GridBagConstraints.BOTH;
		add(jp, gbcRight);

		updateSignatureButton = new JButton("Re-sign");
		updateSignatureButton.setVisible(true);
		gbcRight.gridwidth = 1;
		gbcRight.gridx = 2;
		gbcRight.gridy = 7;
		gbcRight.fill = GridBagConstraints.NONE;
		add(updateSignatureButton, gbcRight);

		chkbxCVEAttack = new JCheckBox("CVE-2018-0114 Attack");
		// TODO: re-enable
		chkbxCVEAttack.setEnabled(false);
		chkbxCVEAttack.setToolTipText("The public and private key used can be found in src/app/helpers/Strings.java");
		chkbxCVEAttack.setHorizontalAlignment(SwingConstants.LEFT);
		gbcRight.anchor = GridBagConstraints.WEST;
		gbcRight.gridwidth = 2;
		gbcRight.fill = GridBagConstraints.HORIZONTAL;
		gbcRight.gridx = 2;
		gbcRight.gridy = 8;
		add(chkbxCVEAttack, gbcRight);


		//TODO: remaining GridBagConstraints
		lblCookieFlags = new JLabel("");
		GridBagConstraints gbc_lblCookieFlag = new GridBagConstraints();
		gbc_lblCookieFlag.insets = new Insets(0, 0, 5, 5);
		gbc_lblCookieFlag.anchor = GridBagConstraints.WEST;
		gbc_lblCookieFlag.gridx = 1;
		gbc_lblCookieFlag.gridy = 9;
		gbc_lblCookieFlag.gridwidth = 2;
		add(lblCookieFlags, gbc_lblCookieFlag);


		lbRegisteredClaims = new JLabel();
		lbRegisteredClaims.setBackground(SystemColor.controlHighlight);
		GridBagConstraints gbc_lbRegisteredClaims = new GridBagConstraints();
		gbc_lbRegisteredClaims.insets = new Insets(5, 5, 5, 5);
		gbc_lbRegisteredClaims.fill = GridBagConstraints.BOTH;
		gbc_lbRegisteredClaims.gridx = 2;
		gbc_lbRegisteredClaims.gridy = 10;
		gbc_lbRegisteredClaims.gridwidth = 2;
		add(lbRegisteredClaims, gbc_lbRegisteredClaims);

		btnCopyPubPrivKeyCVEAttack = new JButton("Copy used public &private key to clipboard used in CVE attack");
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
		btnCopyPubPrivKeyCVEAttack.setVisible(false);
		GridBagConstraints gbc_button = new GridBagConstraints();
		gbc_button.insets = new Insets(0, 0, 0, 5);
		gbc_button.gridx = 1;
		gbc_button.gridy = 13;
		gbc_button.gridwidth = 3;
		add(btnCopyPubPrivKeyCVEAttack, gbc_button);

		lblProblem = new JLabel("");
		GridBagConstraints gbc_lblProblem = new GridBagConstraints();
		gbc_lblProblem.insets = new Insets(0, 0, 5, 5);
		gbc_lblProblem.gridx = 1;
		gbc_lblProblem.gridy = 12;
		gbc_lblProblem.gridwidth = 3;
		add(lblProblem, gbc_lblProblem);
	}

	
	public JComboBox<String> getAlgorithmComboBox() {
		return algorithmComboBox;
	}
	
	public JCheckBox getCVEAttackCheckBox() {
		return chkbxCVEAttack;
	}

	public JButton getCVECopyBtn(){
		return btnCopyPubPrivKeyCVEAttack;
	}

	private void setJWTAreaText() {
		// Remove and re-add ChangeListeners to avoid triggering an ChangeEvent
		AbstractDocument document = (AbstractDocument) jwtArea.getDocument();
		final DocumentListener[] documentListeners = document.getDocumentListeners();
		for (final DocumentListener listener : documentListeners) {
			document.removeDocumentListener(listener);
		}

		if(!jwtArea.getText().equals(jwtIM.getJWTJSON())){
			jwtArea.setText(jwtIM.getJWTJSON());
			//jwtAreaOriginalContent = jwtIM.getJWTJSON();
		}

		for (final DocumentListener listener : documentListeners) {
			document.addDocumentListener(listener);
		}
	}

	private void setKeyAreaText() {
		// Remove and re-add ChangeListeners to avoid triggering an ChangeEvent
		AbstractDocument document = (AbstractDocument) jwtKeyArea.getDocument();
		final DocumentListener[] documentListeners = document.getDocumentListeners();
		for (final DocumentListener listener : documentListeners) {
			document.removeDocumentListener(listener);
		}

		jwtKeyArea.setText(jwtIM.getJWTKey());

		for (final DocumentListener listener : documentListeners) {
			document.addDocumentListener(listener);
		}
	}

	private void setAlgorithmComboBox () {
		String algorithm = null;
		try {
			algorithm = ReadableTokenFormat.getTokenFromReadableFormat(jwtIM.getJWTJSON()).getAlgorithm();
			// Remove and re-add ActionListeners to avoid triggering an ActionEvent
			final ActionListener[] actionListeners = algorithmComboBox.getActionListeners();
			for (final ActionListener listener : actionListeners) {
				algorithmComboBox.removeActionListener(listener);
			}

			algorithmComboBox.setSelectedItem(algorithm);

			for (final ActionListener listener : actionListeners) {
				algorithmComboBox.addActionListener(listener);
			}
		} catch (ReadableTokenFormat.InvalidTokenFormat e) {
			Output.outputError("Exception while setting AlgorithmDropdown: " + e.getMessage());
			e.printStackTrace();
		}

	}

	public void updateSetView(final boolean reset) {
		Output.output("updateSetView()");
		SwingUtilities.invokeLater(new Runnable() {
			public void run() {

				setJWTAreaText();
				setAlgorithmComboBox();
				setKeyAreaText();

				lblProblem.setText(jwtIM.getProblemDetail());

				if(jwtIM.getcFW().isCookie()){
					lblCookieFlags.setText(jwtIM.getcFW().toHTMLString());
				}else{
					lblCookieFlags.setText("");
				}
				lbRegisteredClaims.setText(jwtIM.getTimeClaimsAsText());

				// force repaint to update all elements (i.e. JWT text)
				repaint();
			}
		});
	}
	
	public JTextArea getJwtArea() {
		return jwtArea;
	}
	
	public  RSyntaxTextArea getJwtAreaAsRSyntax() {
		return jwtArea;
	}
	
	public void setKeyFieldState(boolean state){
		jwtKeyArea.setEnabled(state);
	}
	
//	public boolean jwtWasChanged() {
//		if(jwtArea.getText()==null) {
//			return false;
//		}
//		return !jwtAreaOriginalContent.equals(jwtArea.getText());
//	}
//
	public String getJWTfromArea(){
		return jwtArea.getText();
	}
	
	public String getSelectedData() {
		return jwtArea.getSelectedText();
	}

	public String getKeyFieldValue() {
		return jwtKeyArea.getText();
	}
	
	public void setKeyFieldValue(String string) {
		jwtKeyArea.setText(string);
	}
}
package gui;

import java.awt.Color;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;

import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import javax.swing.event.DocumentListener;

import model.JWTTabModel;

import org.fife.ui.rsyntaxtextarea.RSyntaxTextArea;
import org.fife.ui.rsyntaxtextarea.Style;
import org.fife.ui.rsyntaxtextarea.SyntaxConstants;
import org.fife.ui.rsyntaxtextarea.SyntaxScheme;
import org.fife.ui.rsyntaxtextarea.Token;
import org.fife.ui.rtextarea.RTextScrollPane;

import app.algorithm.AlgorithmType;

public class JWTViewTab extends JPanel{

	private static final long serialVersionUID = 1L;
	private RSyntaxTextArea  outputField;
	private JTextField keyField;
	private JLabel outputLabel;
	private JLabel keyLabel;
	private JButton verificationIndicator;
	private JWTTabModel jwtTM;
	private JLabel lblCookieFlags;

	public JWTViewTab(JWTTabModel jwtTM) {
		drawPanel();
		this.jwtTM = jwtTM;
	}

	public void registerDocumentListener(DocumentListener inputFieldListener) {
		keyField.getDocument().addDocumentListener(inputFieldListener);
	}

	
	private void drawPanel() {
		GridBagLayout gridBagLayout = new GridBagLayout();
		gridBagLayout.columnWidths = new int[] { 10, 447, 0, 0 };
		gridBagLayout.rowHeights = new int[] { 10, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
		gridBagLayout.columnWeights = new double[] { 0.0, 1.0, 0.0, Double.MIN_VALUE };
		gridBagLayout.rowWeights = new double[] { 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, Double.MIN_VALUE };
		setLayout(gridBagLayout);
		
		keyLabel = new JLabel(" ");
		keyLabel.setFont(new Font("Tahoma", Font.BOLD, 12));
		GridBagConstraints gbc_inputLabel1 = new GridBagConstraints();
		gbc_inputLabel1.fill = GridBagConstraints.VERTICAL;
		gbc_inputLabel1.insets = new Insets(0, 0, 5, 5);
		gbc_inputLabel1.anchor = GridBagConstraints.WEST;
		gbc_inputLabel1.gridx = 1;
		gbc_inputLabel1.gridy = 1;
		add(keyLabel, gbc_inputLabel1);

		keyField = new JTextField();
		GridBagConstraints gbc_inputField1 = new GridBagConstraints();
		gbc_inputField1.insets = new Insets(0, 0, 5, 5);
		gbc_inputField1.fill = GridBagConstraints.HORIZONTAL;
		gbc_inputField1.gridx = 1;
		gbc_inputField1.gridy = 2;
		add(keyField, gbc_inputField1);
		keyField.setColumns(10);
		
		verificationIndicator = new JButton("");
		Dimension preferredSize = new Dimension(400, 30);
		verificationIndicator.setPreferredSize(preferredSize);
		GridBagConstraints gbc_validIndicator = new GridBagConstraints();
		gbc_validIndicator.insets = new Insets(0, 0, 5, 5);
		gbc_validIndicator.gridx = 1;
		gbc_validIndicator.gridy = 4;
		add(verificationIndicator, gbc_validIndicator);

		outputField = new RSyntaxTextArea();
		SyntaxScheme scheme = outputField.getSyntaxScheme();
		Style style = new Style();
		style.foreground = new Color(222,133,10);
		scheme.setStyle(Token.LITERAL_STRING_DOUBLE_QUOTE, style);
		outputField.revalidate();
		outputField.setHighlightCurrentLine(false);
		outputField.setCurrentLineHighlightColor(Color.WHITE);
		outputField.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_JAVASCRIPT);
		outputField.setEditable(false);
		outputField.setPopupMenu(new JPopupMenu()); // no context menu on right-click
		
		outputLabel = new JLabel("JWT");
		outputLabel.setFont(new Font("Tahoma", Font.BOLD, 12));
		GridBagConstraints gbc_outputLabel = new GridBagConstraints();
		gbc_outputLabel.anchor = GridBagConstraints.WEST;
		gbc_outputLabel.insets = new Insets(0, 0, 5, 5);
		gbc_outputLabel.gridx = 1;
		gbc_outputLabel.gridy = 5;
		add(outputLabel, gbc_outputLabel);
		
		lblCookieFlags = new JLabel(" ");
		lblCookieFlags.setFont(new Font("Tahoma", Font.BOLD, 12));
		GridBagConstraints gbc_lblCookieFlags = new GridBagConstraints();
		gbc_lblCookieFlags.anchor = GridBagConstraints.SOUTHWEST;
		gbc_lblCookieFlags.insets = new Insets(0, 0, 5, 5);
		gbc_lblCookieFlags.gridx = 1;
		gbc_lblCookieFlags.gridy = 8;
		add(lblCookieFlags, gbc_lblCookieFlags);
		
		RTextScrollPane sp = new RTextScrollPane(outputField);
		sp.setLineNumbersEnabled(false);
		
		GridBagConstraints gbc_outputfield = new GridBagConstraints();
		gbc_outputfield.insets = new Insets(0, 0, 5, 5);
		gbc_outputfield.fill = GridBagConstraints.BOTH;
		gbc_outputfield.gridx = 1;
		gbc_outputfield.gridy = 6;
		add(sp, gbc_outputfield);
	}
	

	public JTextArea getOutputfield() {
		return outputField;
	}
		
	public String getKeyValue() {
		return keyField.getText();
	}

	public void setKeyValue(String value) {
		keyField.setText(value);		
	}

	public void setVerificationResult(String value) {
		verificationIndicator.setText(value);
	}

	public void setVerificationResultColor(Color verificationResultColor) {
		verificationIndicator.setBackground(verificationResultColor);
	}

	public void setCaret() {
		outputField.setCaretPosition(0);
	}

	public String getSelectedData() {
		return getOutputfield().getSelectedText();
	}

	
	public void updateSetView(final String algorithmType) {
		SwingUtilities.invokeLater(new Runnable() {
			public void run() {
				if(!jwtTM.getJWTJSON().equals(outputField.getText())){
					outputField.setText(jwtTM.getJWTJSON());
				}
				if(!jwtTM.getKeyLabel().equals(keyLabel.getText())){
					keyLabel.setText(jwtTM.getKeyLabel());
				}
				if(!jwtTM.getKey().equals(keyField.getText())){
					keyField.setText(jwtTM.getKey());
				}
				if(!jwtTM.getVerificationColor().equals(verificationIndicator.getBackground())){
					verificationIndicator.setBackground(jwtTM.getVerificationColor());
				}
				if(!jwtTM.getVerificationLabel().equals(verificationIndicator.getText())){
					verificationIndicator.setText(jwtTM.getVerificationLabel());
				}
				if(algorithmType.equals(AlgorithmType.symmetric)){
					keyLabel.setText("Secret");
					keyField.setEnabled(true);
				}
				if(algorithmType.equals(AlgorithmType.asymmetric)){
					keyLabel.setText("Public Key");
					keyField.setEnabled(true);
				}
				if(algorithmType.equals(AlgorithmType.none)){
					keyLabel.setText("");
					keyField.setEnabled(false);
					keyField.setEnabled(false);
				}
				
				if(jwtTM.getcFW().isCookie()){
					lblCookieFlags.setText(jwtTM.getcFW().toHTMLString());
				}else{
					lblCookieFlags.setText("");
				}
				setCaret();
			}
		});
	}

}

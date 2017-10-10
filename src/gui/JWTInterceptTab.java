package gui;

import java.awt.Color;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionListener;

import javax.swing.AbstractButton;
import javax.swing.ButtonGroup;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JRadioButton;
import javax.swing.JSeparator;
import javax.swing.JTextField;
import javax.swing.SwingConstants;
import javax.swing.SwingUtilities;

import model.JWTInterceptModel;

import org.fife.ui.rsyntaxtextarea.RSyntaxTextArea;
import org.fife.ui.rsyntaxtextarea.Style;
import org.fife.ui.rsyntaxtextarea.SyntaxConstants;
import org.fife.ui.rsyntaxtextarea.SyntaxScheme;
import org.fife.ui.rsyntaxtextarea.Token;
import org.fife.ui.rtextarea.RTextScrollPane;

import app.helpers.Strings;

public class JWTInterceptTab extends JPanel {

	private static final long serialVersionUID = 1L;
	private JWTInterceptModel jwtIM;
	private RSyntaxTextArea jwtArea;
	private JRadioButton rdbtnRecalculateSignature;
	private JRadioButton rdbtnRandomKey;
	private JRadioButton rdbtnOriginalSignature;
	private JTextField keyField;
	private JLabel lblSecretKey;
	private JSeparator separator;
	private JRadioButton rdbtnDontModifySignature;
	private JLabel lblProblem;
	private JComboBox<String> noneAttackComboBox;
	private JLabel lblNewLabel;
	private JLabel lblCookieFlags;

	public JWTInterceptTab(JWTInterceptModel jwtIM) {
		this.jwtIM = jwtIM;
		drawGui();
	}
	
	public void registerActionListeners(ActionListener dontMofiy, ActionListener randomKeyListener, ActionListener originalSignatureListener, ActionListener recalculateSignatureListener, ActionListener algAttackListener){
		rdbtnDontModifySignature.addActionListener(dontMofiy);
		rdbtnRecalculateSignature.addActionListener(randomKeyListener);
		rdbtnOriginalSignature.addActionListener(originalSignatureListener);
		rdbtnRandomKey.addActionListener(recalculateSignatureListener);
		noneAttackComboBox.addActionListener(algAttackListener);
	}
	
	private void drawGui() {	
		GridBagLayout gridBagLayout = new GridBagLayout();
		gridBagLayout.columnWidths = new int[]{10, 0, 0, 20, 0};
		gridBagLayout.rowHeights = new int[]{10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
		gridBagLayout.columnWeights = new double[]{0.0, 1.0, 1.0, 0.0, Double.MIN_VALUE};
		gridBagLayout.rowWeights = new double[]{0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, Double.MIN_VALUE};
		setLayout(gridBagLayout);
		
		jwtArea = new RSyntaxTextArea ();
		jwtArea.setColumns(20);
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
		sp.setLineNumbersEnabled(false);
		
		GridBagConstraints gbc_jwtArea = new GridBagConstraints();
		gbc_jwtArea.gridheight = 7;
		gbc_jwtArea.insets = new Insets(0, 0, 5, 5);
		gbc_jwtArea.fill = GridBagConstraints.BOTH;
		gbc_jwtArea.gridx = 1;
		gbc_jwtArea.gridy = 1;
		add(sp, gbc_jwtArea);
		
		rdbtnDontModifySignature = new JRadioButton(Strings.dontModify);
		rdbtnDontModifySignature.setToolTipText(Strings.dontModifyToolTip);
		rdbtnDontModifySignature.setSelected(true);
		rdbtnDontModifySignature.setHorizontalAlignment(SwingConstants.LEFT);
		GridBagConstraints gbc_rdbtnDontModifySignature = new GridBagConstraints();
		gbc_rdbtnDontModifySignature.anchor = GridBagConstraints.WEST;
		gbc_rdbtnDontModifySignature.insets = new Insets(0, 0, 5, 5);
		gbc_rdbtnDontModifySignature.gridx = 2;
		gbc_rdbtnDontModifySignature.gridy = 1;
		add(rdbtnDontModifySignature, gbc_rdbtnDontModifySignature);
		
		rdbtnRecalculateSignature = new JRadioButton(Strings.recalculateSignature);
		rdbtnRecalculateSignature.setToolTipText(Strings.recalculateSignatureToolTip);
		rdbtnRecalculateSignature.setHorizontalAlignment(SwingConstants.LEFT);
		GridBagConstraints gbc_rdbtnRecalculateSignature = new GridBagConstraints();
		gbc_rdbtnRecalculateSignature.anchor = GridBagConstraints.WEST;
		gbc_rdbtnRecalculateSignature.insets = new Insets(0, 0, 5, 5);
		gbc_rdbtnRecalculateSignature.gridx = 2;
		gbc_rdbtnRecalculateSignature.gridy = 2;
		add(rdbtnRecalculateSignature, gbc_rdbtnRecalculateSignature);
		
		rdbtnOriginalSignature = new JRadioButton(Strings.keepOriginalSignature);
		rdbtnOriginalSignature.setToolTipText(Strings.keepOriginalSignatureToolTip);
		rdbtnOriginalSignature.setHorizontalAlignment(SwingConstants.LEFT);
		GridBagConstraints gbc_rdbtnNewRadioButton_1 = new GridBagConstraints();
		gbc_rdbtnNewRadioButton_1.insets = new Insets(0, 0, 5, 5);
		gbc_rdbtnNewRadioButton_1.anchor = GridBagConstraints.WEST;
		gbc_rdbtnNewRadioButton_1.gridx = 2;
		gbc_rdbtnNewRadioButton_1.gridy = 3;
		add(rdbtnOriginalSignature, gbc_rdbtnNewRadioButton_1);
		
		rdbtnRandomKey = new JRadioButton(Strings.randomKey);
		rdbtnRandomKey.setToolTipText(Strings.randomKeyToolTip);
		rdbtnRandomKey.setHorizontalAlignment(SwingConstants.LEFT);
		GridBagConstraints gbc_rdbtnNewRadioButton = new GridBagConstraints();
		gbc_rdbtnNewRadioButton.anchor = GridBagConstraints.WEST;
		gbc_rdbtnNewRadioButton.insets = new Insets(0, 0, 5, 5);
		gbc_rdbtnNewRadioButton.gridx = 2;
		gbc_rdbtnNewRadioButton.gridy = 4;
		add(rdbtnRandomKey, gbc_rdbtnNewRadioButton);
		
		ButtonGroup btgrp = new ButtonGroup();
		btgrp.add(rdbtnDontModifySignature);
		btgrp.add(rdbtnOriginalSignature);
		btgrp.add(rdbtnRandomKey);
		btgrp.add(rdbtnRecalculateSignature);
		
		separator = new JSeparator();
		GridBagConstraints gbc_separator = new GridBagConstraints();
		gbc_separator.insets = new Insets(0, 0, 5, 5);
		gbc_separator.gridx = 2;
		gbc_separator.gridy = 5;
		add(separator, gbc_separator);
		
		lblSecretKey = new JLabel(Strings.interceptRecalculationKey);
		GridBagConstraints gbc_lblSecretKey = new GridBagConstraints();
		gbc_lblSecretKey.insets = new Insets(0, 0, 5, 5);
		gbc_lblSecretKey.anchor = GridBagConstraints.SOUTHWEST;
		gbc_lblSecretKey.gridx = 2;
		gbc_lblSecretKey.gridy = 6;
		add(lblSecretKey, gbc_lblSecretKey);
		
		keyField = new JTextField();
		keyField.setEnabled(false);
		GridBagConstraints gbc_keyField = new GridBagConstraints();
		gbc_keyField.anchor = GridBagConstraints.NORTH;
		gbc_keyField.insets = new Insets(0, 0, 5, 5);
		gbc_keyField.fill = GridBagConstraints.HORIZONTAL;
		gbc_keyField.gridx = 2;
		gbc_keyField.gridy = 7;
		add(keyField, gbc_keyField);
		keyField.setColumns(10);
		
		lblProblem = new JLabel("");
		GridBagConstraints gbc_lblProblem = new GridBagConstraints();
		gbc_lblProblem.insets = new Insets(0, 0, 5, 5);
		gbc_lblProblem.gridx = 1;
		gbc_lblProblem.gridy = 8;
		add(lblProblem, gbc_lblProblem);
		
		lblNewLabel = new JLabel("Alg None Attack:");
		GridBagConstraints gbc_lblNewLabel = new GridBagConstraints();
		gbc_lblNewLabel.anchor = GridBagConstraints.WEST;
		gbc_lblNewLabel.insets = new Insets(0, 0, 5, 5);
		gbc_lblNewLabel.gridx = 2;
		gbc_lblNewLabel.gridy = 9;
		add(lblNewLabel, gbc_lblNewLabel);
		
		lblCookieFlags = new JLabel("");
		GridBagConstraints gbc_lblCookieFlag = new GridBagConstraints();
		gbc_lblCookieFlag.insets = new Insets(0, 0, 5, 5);
		gbc_lblCookieFlag.anchor = GridBagConstraints.WEST;
		gbc_lblCookieFlag.gridx = 1;
		gbc_lblCookieFlag.gridy = 10;
		add(lblCookieFlags, gbc_lblCookieFlag);
		
		noneAttackComboBox = new JComboBox<String>();
		GridBagConstraints gbc_noneAttackComboBox = new GridBagConstraints();
		gbc_noneAttackComboBox.insets = new Insets(0, 0, 5, 5);
		gbc_noneAttackComboBox.fill = GridBagConstraints.HORIZONTAL;
		gbc_noneAttackComboBox.gridx = 2;
		gbc_noneAttackComboBox.gridy = 10;
		add(noneAttackComboBox, gbc_noneAttackComboBox);
		
		noneAttackComboBox.addItem("  -");
		noneAttackComboBox.addItem("Alg: none");
		noneAttackComboBox.addItem("Alg: None");
		noneAttackComboBox.addItem("Alg: nOnE");
		noneAttackComboBox.addItem("Alg: NONE");
		
	}
	
	public AbstractButton getRdbtnDontModify() {
		return rdbtnDontModifySignature;
	}
	
	public JRadioButton getRdbtnRecalculateSignature() {
		return rdbtnRecalculateSignature;
	}
	
	public JComboBox<String> getNoneAttackComboBox() {
		return noneAttackComboBox;
	}

	public JRadioButton getRdbtnRandomKey() {
		return rdbtnRandomKey;
	}

	public JRadioButton getRdbtnOriginalSignature() {
		return rdbtnOriginalSignature;
	}

	public void updateSetView(final boolean reset) {
		SwingUtilities.invokeLater(new Runnable() {
			public void run() {
				if(!jwtArea.getText().equals(jwtIM.getJWTJSON())){
					jwtArea.setText(jwtIM.getJWTJSON());
				}
				keyField.setText(jwtIM.getJWTKey());
				if(reset){
					rdbtnDontModifySignature.setSelected(true);
					keyField.setText("");
					keyField.setEnabled(false);
				}
				jwtArea.setCaretPosition(0);
				lblProblem.setText(jwtIM.getProblemDetail());
				
				if(jwtIM.getcFW().isCookie()){
					lblCookieFlags.setText(jwtIM.getcFW().toHTMLString());
				}else{
					lblCookieFlags.setText("");
				}
			}
		});
	}
	
	public void setKeyFieldState(boolean state){
		keyField.setEnabled(state);
	}
	
	public String getJWTfromArea(){
		return jwtArea.getText();
	}
	
	public String getSelectedData() {
		return jwtArea.getSelectedText();
	}

	public String getKeyFieldValue() {
		return keyField.getText();
	}
	
	public void setKeyFieldValue(String string) {
		keyField.setText(string);
	}
}
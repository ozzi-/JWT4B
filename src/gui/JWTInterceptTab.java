package gui;

import java.awt.Color;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionListener;

import javax.swing.AbstractButton;
import javax.swing.ButtonGroup;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JRadioButton;
import javax.swing.JSeparator;
import javax.swing.JTextField;
import javax.swing.SwingConstants;
import javax.swing.SwingUtilities;

import org.fife.ui.rsyntaxtextarea.RSyntaxTextArea;
import org.fife.ui.rsyntaxtextarea.Style;
import org.fife.ui.rsyntaxtextarea.SyntaxConstants;
import org.fife.ui.rsyntaxtextarea.SyntaxScheme;
import org.fife.ui.rsyntaxtextarea.Token;
import org.fife.ui.rtextarea.RTextScrollPane;

import app.helpers.Strings;
import model.JWTInterceptModel;

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

	public JWTInterceptTab(JWTInterceptModel jwtIM) {
		this.jwtIM = jwtIM;
		drawGui();
	}
	
	public void registerActionListeners(ActionListener dontMofiy, ActionListener randomKeyListener, ActionListener originalSignatureListener, ActionListener recalculateSignatureListener){
		rdbtnDontModifySignature.addActionListener(dontMofiy);
		rdbtnRecalculateSignature.addActionListener(randomKeyListener);
		rdbtnOriginalSignature.addActionListener(originalSignatureListener);
		rdbtnRandomKey.addActionListener(recalculateSignatureListener);
	}
	
	private void drawGui() {	
		GridBagLayout gridBagLayout = new GridBagLayout();
		gridBagLayout.columnWidths = new int[]{0, 0, 0};
		gridBagLayout.rowHeights = new int[]{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
		gridBagLayout.columnWeights = new double[]{1.0, 1.0, Double.MIN_VALUE};
		gridBagLayout.rowWeights = new double[]{0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, Double.MIN_VALUE};
		setLayout(gridBagLayout);
		
		jwtArea = new RSyntaxTextArea ();
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
		gbc_jwtArea.gridx = 0;
		gbc_jwtArea.gridy = 0;
		add(jwtArea, gbc_jwtArea);
		
		rdbtnDontModifySignature = new JRadioButton("Don't automatically modify signature");
		rdbtnDontModifySignature.setToolTipText(Strings.dontModifyToolTip);
		rdbtnDontModifySignature.setSelected(true);
		rdbtnDontModifySignature.setHorizontalAlignment(SwingConstants.LEFT);
		GridBagConstraints gbc_rdbtnDontModifySignature = new GridBagConstraints();
		gbc_rdbtnDontModifySignature.anchor = GridBagConstraints.WEST;
		gbc_rdbtnDontModifySignature.insets = new Insets(0, 0, 5, 0);
		gbc_rdbtnDontModifySignature.gridx = 1;
		gbc_rdbtnDontModifySignature.gridy = 0;
		add(rdbtnDontModifySignature, gbc_rdbtnDontModifySignature);
		
		rdbtnRecalculateSignature = new JRadioButton("Recalculate signature");
		rdbtnRecalculateSignature.setToolTipText(Strings.recalculateSignatureToolTip);
		rdbtnRecalculateSignature.setHorizontalAlignment(SwingConstants.LEFT);
		GridBagConstraints gbc_rdbtnRecalculateSignature = new GridBagConstraints();
		gbc_rdbtnRecalculateSignature.anchor = GridBagConstraints.WEST;
		gbc_rdbtnRecalculateSignature.insets = new Insets(0, 0, 5, 0);
		gbc_rdbtnRecalculateSignature.gridx = 1;
		gbc_rdbtnRecalculateSignature.gridy = 1;
		add(rdbtnRecalculateSignature, gbc_rdbtnRecalculateSignature);
		
		rdbtnOriginalSignature = new JRadioButton("Keep original signature");
		rdbtnOriginalSignature.setToolTipText(Strings.originalSignatureToolTip);
		rdbtnOriginalSignature.setHorizontalAlignment(SwingConstants.LEFT);
		GridBagConstraints gbc_rdbtnNewRadioButton_1 = new GridBagConstraints();
		gbc_rdbtnNewRadioButton_1.insets = new Insets(0, 0, 5, 0);
		gbc_rdbtnNewRadioButton_1.anchor = GridBagConstraints.WEST;
		gbc_rdbtnNewRadioButton_1.gridx = 1;
		gbc_rdbtnNewRadioButton_1.gridy = 2;
		add(rdbtnOriginalSignature, gbc_rdbtnNewRadioButton_1);
		
		rdbtnRandomKey = new JRadioButton("Sign with random key pair");
		rdbtnRandomKey.setToolTipText(Strings.randomKeyToolTip);
		rdbtnRandomKey.setHorizontalAlignment(SwingConstants.LEFT);
		GridBagConstraints gbc_rdbtnNewRadioButton = new GridBagConstraints();
		gbc_rdbtnNewRadioButton.anchor = GridBagConstraints.WEST;
		gbc_rdbtnNewRadioButton.insets = new Insets(0, 0, 5, 0);
		gbc_rdbtnNewRadioButton.gridx = 1;
		gbc_rdbtnNewRadioButton.gridy = 3;
		add(rdbtnRandomKey, gbc_rdbtnNewRadioButton);
		
		ButtonGroup btgrp = new ButtonGroup();
		btgrp.add(rdbtnDontModifySignature);
		btgrp.add(rdbtnOriginalSignature);
		btgrp.add(rdbtnRandomKey);
		btgrp.add(rdbtnRecalculateSignature);
		
		separator = new JSeparator();
		GridBagConstraints gbc_separator = new GridBagConstraints();
		gbc_separator.insets = new Insets(0, 0, 5, 0);
		gbc_separator.gridx = 1;
		gbc_separator.gridy = 4;
		add(separator, gbc_separator);
		
		lblSecretKey = new JLabel(Strings.interceptRecalculationKey);
		GridBagConstraints gbc_lblSecretKey = new GridBagConstraints();
		gbc_lblSecretKey.insets = new Insets(0, 0, 5, 0);
		gbc_lblSecretKey.anchor = GridBagConstraints.SOUTHWEST;
		gbc_lblSecretKey.gridx = 1;
		gbc_lblSecretKey.gridy = 5;
		add(lblSecretKey, gbc_lblSecretKey);
		
		keyField = new JTextField();
		keyField.setEnabled(false);
		GridBagConstraints gbc_keyField = new GridBagConstraints();
		gbc_keyField.anchor = GridBagConstraints.NORTH;
		gbc_keyField.insets = new Insets(0, 0, 5, 0);
		gbc_keyField.fill = GridBagConstraints.HORIZONTAL;
		gbc_keyField.gridx = 1;
		gbc_keyField.gridy = 6;
		add(keyField, gbc_keyField);
		keyField.setColumns(10);
		
	}
	
	public AbstractButton getRdbtnDontModify() {
		return rdbtnDontModifySignature;
	}
	
	public JRadioButton getRdbtnRecalculateSignature() {
		return rdbtnRecalculateSignature;
	}

	public JRadioButton getRdbtnRandomKey() {
		return rdbtnRandomKey;
	}

	public JRadioButton getRdbtnOriginalSignature() {
		return rdbtnOriginalSignature;
	}

	public void updateSetView() {
		SwingUtilities.invokeLater(new Runnable() {
			public void run() {
				if(!jwtArea.getText().equals(jwtIM.getJWTJSON())){
					jwtArea.setText(jwtIM.getJWTJSON());
				}
				keyField.setText(jwtIM.getJWTKey());
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

	public void setKeyFieldValue(String string) {
		keyField.setText(string);
	}


}

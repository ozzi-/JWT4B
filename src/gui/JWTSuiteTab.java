package gui;

import javax.swing.JPanel;
import java.awt.GridBagLayout;
import javax.swing.JLabel;
import java.awt.GridBagConstraints;
import javax.swing.JTextField;
import java.awt.Insets;
import java.util.Observable;
import java.util.Observer;

import javax.swing.JTextPane;

import app.controllers.JWTMessageEditorTabController;
import app.controllers.JWTSuiteTabController;
import app.helpers.ConsoleOut;

public class JWTSuiteTab  extends JPanel implements Observer  {
	
	private static final long serialVersionUID = 1L;
	private JTextField textField;
	private JWTSuiteTabController sTC;
	
	public JWTSuiteTab(JWTSuiteTabController sTC) {
		this.sTC = sTC;
		sTC.addObserver(this); 
		drawGui();
	}
	
	private void drawGui() {
		GridBagLayout gridBagLayout = new GridBagLayout();
		gridBagLayout.columnWidths = new int[]{0, 0, 0, 0, 0, 0};
		gridBagLayout.rowHeights = new int[]{0, 0, 0, 0, 0, 0};
		gridBagLayout.columnWeights = new double[]{0.0, 0.0, 0.0, 1.0, 1.0, Double.MIN_VALUE};
		gridBagLayout.rowWeights = new double[]{0.0, 0.0, 0.0, 1.0, 0.0, Double.MIN_VALUE};
		setLayout(gridBagLayout);
		
		JLabel lblPasteJwtToken = new JLabel("Paste JWT Token");
		GridBagConstraints gbc_lblPasteJwtToken = new GridBagConstraints();
		gbc_lblPasteJwtToken.insets = new Insets(0, 0, 5, 5);
		gbc_lblPasteJwtToken.gridx = 1;
		gbc_lblPasteJwtToken.gridy = 1;
		add(lblPasteJwtToken, gbc_lblPasteJwtToken);
		
		textField = new JTextField();
		GridBagConstraints gbc_textField = new GridBagConstraints();
		gbc_textField.insets = new Insets(0, 0, 5, 5);
		gbc_textField.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField.gridx = 3;
		gbc_textField.gridy = 1;
		add(textField, gbc_textField);
		textField.setColumns(10);
		
		JLabel lblDecodedJwt = new JLabel("Decoded JWT");
		GridBagConstraints gbc_lblDecodedJwt = new GridBagConstraints();
		gbc_lblDecodedJwt.insets = new Insets(0, 0, 5, 5);
		gbc_lblDecodedJwt.gridx = 1;
		gbc_lblDecodedJwt.gridy = 3;
		add(lblDecodedJwt, gbc_lblDecodedJwt);
			
		JTextPane textPane = new JTextPane();
		GridBagConstraints gbc_textPane = new GridBagConstraints();
		gbc_textPane.insets = new Insets(0, 0, 5, 5);
		gbc_textPane.fill = GridBagConstraints.BOTH;
		gbc_textPane.gridx = 3;
		gbc_textPane.gridy = 3;
		add(textPane, gbc_textPane);
	}

	public JTextField getTextField() {
		return textField;
	}

	@Override
	public void update(Observable o, Object arg) {
		String selectedText = (String) arg; // TODO notify types, check cast
		textField.setText(selectedText);
	}	
}

package gui;

import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;

import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextArea;
import javax.swing.JTextPane;

import app.helpers.Strings;

public class JWTSuiteTab extends JPanel {

	private static final long serialVersionUID = 1L;
	private JTextArea jwtInputField;
	private JTextPane jwtOuputField;

	public JWTSuiteTab() {
		drawGui();
	}

	private void drawGui() {
		GridBagLayout gridBagLayout = new GridBagLayout();
		gridBagLayout.columnWidths = new int[] { 0, 0, 0, 0 };
		gridBagLayout.rowHeights = new int[] { 0, 0, 0, 0, 0, 0 };
		gridBagLayout.columnWeights = new double[] { 0.0, 0.0, 1.0, Double.MIN_VALUE };
		gridBagLayout.rowWeights = new double[] { 0.0, 0.0, 0.0, 1.0, 0.0, Double.MIN_VALUE };
		setLayout(gridBagLayout);

		JLabel lblPasteJwtToken = new JLabel(Strings.enterJWT);
		GridBagConstraints gbc_lblPasteJwtToken = new GridBagConstraints();
		gbc_lblPasteJwtToken.insets = new Insets(0, 0, 5, 5);
		gbc_lblPasteJwtToken.gridx = 0;
		gbc_lblPasteJwtToken.gridy = 1;
		add(lblPasteJwtToken, gbc_lblPasteJwtToken);

		jwtInputField = new JTextArea();
		jwtInputField.setRows(2);
		jwtInputField.setLineWrap(true);
		jwtInputField.setWrapStyleWord(true);

		GridBagConstraints gbc_jwtInputField = new GridBagConstraints();
		gbc_jwtInputField.insets = new Insets(0, 0, 5, 0);
		gbc_jwtInputField.fill = GridBagConstraints.BOTH;
		gbc_jwtInputField.gridx = 2;
		gbc_jwtInputField.gridy = 1;
		add(jwtInputField, gbc_jwtInputField);

		JLabel lblDecodedJwt = new JLabel(Strings.decodedJWT);
		GridBagConstraints gbc_lblDecodedJwt = new GridBagConstraints();
		gbc_lblDecodedJwt.insets = new Insets(0, 0, 5, 5);
		gbc_lblDecodedJwt.gridx = 0;
		gbc_lblDecodedJwt.gridy = 3;
		add(lblDecodedJwt, gbc_lblDecodedJwt);

		jwtOuputField = new JTextPane();
		GridBagConstraints gbc_jwtOuputField = new GridBagConstraints();
		gbc_jwtOuputField.insets = new Insets(0, 0, 5, 0);
		gbc_jwtOuputField.fill = GridBagConstraints.BOTH;
		gbc_jwtOuputField.gridx = 2;
		gbc_jwtOuputField.gridy = 3;
		add(jwtOuputField, gbc_jwtOuputField);
	}

	public JTextArea getInputField() {
		return jwtInputField;
	}
	
	public JTextPane getOuputField() {
		return jwtOuputField;
	}

}

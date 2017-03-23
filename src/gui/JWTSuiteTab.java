package gui;

import java.awt.Color;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.KeyListener;

import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;

import org.fife.ui.rsyntaxtextarea.RSyntaxTextArea;
import org.fife.ui.rsyntaxtextarea.SyntaxConstants;
import org.fife.ui.rtextarea.RTextScrollPane;

import app.helpers.Strings;
import model.JWTSuiteTabModel;

public class JWTSuiteTab extends JPanel {

	private static final long serialVersionUID = 1L;
	private JTextArea jwtInputField;
	private RSyntaxTextArea jwtOuputField;
	private JButton jwtSignatureButton;
	private JTextField jwtKeyField;
	private JLabel lblEnterSecret;
	private JWTSuiteTabModel jwtSTM;

	public JWTSuiteTab(JWTSuiteTabModel jwtSTM) {
		this.jwtSTM = jwtSTM;
		drawGui();
	}
	
	public void updateSetView(){
		SwingUtilities.invokeLater(new Runnable() {
			public void run() {
				jwtInputField.setText(jwtSTM.getJwtInput());
				jwtOuputField.setText(jwtSTM.getJwtJSON());
				jwtKeyField.setText(jwtSTM.getJwtKey());
				jwtSignatureButton.setBackground(jwtSTM.getJwtSignatureColor());
			}
		});

	}

	public void registerDocumentListener(KeyListener jwtInputListener, KeyListener jwtKeyListener) {
		jwtInputField.addKeyListener(jwtInputListener);
		jwtKeyField.addKeyListener(jwtKeyListener);
	}

	private void drawGui() {
		GridBagLayout gridBagLayout = new GridBagLayout();
		gridBagLayout.columnWidths = new int[] { 0, 0, 0, 0 };
		gridBagLayout.rowHeights = new int[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
		gridBagLayout.columnWeights = new double[] { 0.0, 0.0, 1.0, Double.MIN_VALUE };
		gridBagLayout.rowWeights = new double[] { 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, Double.MIN_VALUE };
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

		lblEnterSecret = new JLabel("Enter Secret / Key");
		GridBagConstraints gbc_lblEnterSecret = new GridBagConstraints();
		gbc_lblEnterSecret.insets = new Insets(0, 0, 5, 5);
		gbc_lblEnterSecret.gridx = 0;
		gbc_lblEnterSecret.gridy = 3;
		add(lblEnterSecret, gbc_lblEnterSecret);

		jwtKeyField = new JTextField();
		GridBagConstraints gbc_jwtKeyField = new GridBagConstraints();
		gbc_jwtKeyField.insets = new Insets(0, 0, 5, 0);
		gbc_jwtKeyField.fill = GridBagConstraints.HORIZONTAL;
		gbc_jwtKeyField.gridx = 2;
		gbc_jwtKeyField.gridy = 3;
		add(jwtKeyField, gbc_jwtKeyField);
		jwtKeyField.setColumns(10);

		jwtSignatureButton = new JButton("                  ");
		GridBagConstraints gbc_jwtSignatureButton = new GridBagConstraints();
		gbc_jwtSignatureButton.insets = new Insets(0, 0, 5, 0);
		gbc_jwtSignatureButton.gridx = 2;
		gbc_jwtSignatureButton.gridy = 5;
		add(jwtSignatureButton, gbc_jwtSignatureButton);

		JLabel lblDecodedJwt = new JLabel(Strings.decodedJWT);
		GridBagConstraints gbc_lblDecodedJwt = new GridBagConstraints();
		gbc_lblDecodedJwt.insets = new Insets(0, 0, 5, 5);
		gbc_lblDecodedJwt.gridx = 0;
		gbc_lblDecodedJwt.gridy = 7;
		add(lblDecodedJwt, gbc_lblDecodedJwt);

		GridBagConstraints gbc_jwtOuputField = new GridBagConstraints();
		gbc_jwtOuputField.insets = new Insets(0, 0, 5, 0);
		gbc_jwtOuputField.fill = GridBagConstraints.BOTH;
		gbc_jwtOuputField.gridx = 2;
		gbc_jwtOuputField.gridy = 7;

		jwtOuputField = new RSyntaxTextArea();
		jwtOuputField.setHighlightCurrentLine(false);
		jwtOuputField.setCurrentLineHighlightColor(Color.WHITE);
		jwtOuputField.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_JAVASCRIPT);
		jwtOuputField.setEditable(false);
		jwtOuputField.setPopupMenu(new JPopupMenu()); // no context menu on
														// right-click
		RTextScrollPane sp = new RTextScrollPane(jwtOuputField);
		sp.setLineNumbersEnabled(false);

		add(jwtOuputField, gbc_jwtOuputField);

	}
}

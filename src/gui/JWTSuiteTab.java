package gui;

import java.awt.Color;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;

import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JTextArea;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

import org.fife.ui.rsyntaxtextarea.RSyntaxTextArea;
import org.fife.ui.rsyntaxtextarea.SyntaxConstants;
import org.fife.ui.rtextarea.RTextScrollPane;

import app.controllers.JWTSuiteTabController;
import app.helpers.Strings;

public class JWTSuiteTab extends JPanel {

	private static final long serialVersionUID = 1L;
	private JTextArea jwtInputField;
	private RSyntaxTextArea jwtOuputField;
	private JWTSuiteTabController jwtSuiteTabController;

	public JWTSuiteTab(JWTSuiteTabController jwtSuiteTabController) {
		this.jwtSuiteTabController=jwtSuiteTabController;
		drawGui();
		registerDocumentListener();
	}
	
	private void registerDocumentListener() {
		jwtInputField.getDocument().addDocumentListener(new DocumentListener() {
			public void changedUpdate(DocumentEvent e) {
				jwtSuiteTabController.contextAction(jwtInputField.getText());
			}
			public void removeUpdate(DocumentEvent e) {
				jwtSuiteTabController.contextAction(jwtInputField.getText());
			}
			public void insertUpdate(DocumentEvent e) {
				jwtSuiteTabController.contextAction(jwtInputField.getText());
			}
		});
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

		
		GridBagConstraints gbc_jwtOuputField = new GridBagConstraints();
		gbc_jwtOuputField.insets = new Insets(0, 0, 5, 0);
		gbc_jwtOuputField.fill = GridBagConstraints.BOTH;
		gbc_jwtOuputField.gridx = 2;
		gbc_jwtOuputField.gridy = 3;
				
		jwtOuputField = new RSyntaxTextArea();
		jwtOuputField.setHighlightCurrentLine(false);
		jwtOuputField.setCurrentLineHighlightColor(Color.WHITE);
		jwtOuputField.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_JAVASCRIPT);
		jwtOuputField.setEditable(false);
		jwtOuputField.setPopupMenu(new JPopupMenu()); // no context menu on right-click
		RTextScrollPane sp = new RTextScrollPane(jwtOuputField);
		sp.setLineNumbersEnabled(false);
		
		add(jwtOuputField, gbc_jwtOuputField);

		
	}

	public JTextArea getInputField() {
		return jwtInputField;
	}
	
	public RSyntaxTextArea getOuputField() {
		return jwtOuputField;
	}

}

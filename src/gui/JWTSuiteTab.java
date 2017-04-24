package gui;

import java.awt.Color;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import javax.swing.event.DocumentListener;

import org.fife.ui.rsyntaxtextarea.RSyntaxTextArea;
import org.fife.ui.rsyntaxtextarea.Style;
import org.fife.ui.rsyntaxtextarea.SyntaxConstants;
import org.fife.ui.rsyntaxtextarea.SyntaxScheme;
import org.fife.ui.rsyntaxtextarea.Token;
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
	private JButton creditButton;

	public JWTSuiteTab(JWTSuiteTabModel jwtSTM) {
		drawGui();
		this.jwtSTM = jwtSTM;
	}
	
	public void updateSetView(){
		SwingUtilities.invokeLater(new Runnable() {
			public void run() {
				if(!jwtInputField.getText().equals(jwtSTM.getJwtInput())){
					jwtInputField.setText(jwtSTM.getJwtInput());					
				}
				if(!jwtSignatureButton.getText().equals(jwtSTM.getVerificationLabel())){
					jwtSignatureButton.setText(jwtSTM.getVerificationLabel());
				}
				if(!jwtOuputField.getText().equals(jwtSTM.getJwtJSON())){
					jwtOuputField.setText(jwtSTM.getJwtJSON());					
				}
				if(!jwtKeyField.getText().equals(jwtSTM.getJwtKey())){
					jwtKeyField.setText(jwtSTM.getJwtKey());					
				}
				if(!jwtSignatureButton.getBackground().equals(jwtSTM.getJwtSignatureColor())){
					jwtSignatureButton.setBackground(jwtSTM.getJwtSignatureColor());					
				}
				if(jwtKeyField.getText().equals("")){
					jwtSTM.setJwtSignatureColor(new JButton().getBackground());
					jwtSignatureButton.setBackground(jwtSTM.getJwtSignatureColor());
				}
			}
		});
	}

	public void registerDocumentListener(DocumentListener jwtInputListener,DocumentListener jwtKeyListener) {
		jwtInputField.getDocument().addDocumentListener(jwtInputListener);
		jwtKeyField.getDocument().addDocumentListener(jwtKeyListener);
	}

	private void drawGui() {
		GridBagLayout gridBagLayout = new GridBagLayout();
		gridBagLayout.columnWidths = new int[] { 10, 0, 0, 0 };
		gridBagLayout.rowHeights = new int[] { 30, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
		gridBagLayout.columnWeights = new double[] { 0.0, 1.0, 0.0, Double.MIN_VALUE };
		gridBagLayout.rowWeights = new double[] { 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, Double.MIN_VALUE };
		setLayout(gridBagLayout);
		
		JLabel lblPasteJwtToken = new JLabel(Strings.enterJWT);
		lblPasteJwtToken.setFont(new Font("Tahoma", Font.BOLD, 12));
		GridBagConstraints gbc_lblPasteJwtToken = new GridBagConstraints();
		gbc_lblPasteJwtToken.anchor = GridBagConstraints.SOUTHWEST;
		gbc_lblPasteJwtToken.insets = new Insets(0, 0, 5, 5);
		gbc_lblPasteJwtToken.gridx = 1;
		gbc_lblPasteJwtToken.gridy = 0;
		add(lblPasteJwtToken, gbc_lblPasteJwtToken);
		
		creditButton = new JButton("?");
		creditButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				JFrame frame = new JFrame();
				frame.setTitle(Strings.creditTitle);
				frame.setVisible(true);
				frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
				frame.setBounds(0, 0, 550, 420);
				frame.setLocationRelativeTo(null);
				GridBagLayout gridBagLayout = new GridBagLayout();
				gridBagLayout.columnWidths = new int[]{59, 534, 36, 0};
				gridBagLayout.rowHeights = new int[]{0, 97, 0};
				gridBagLayout.columnWeights = new double[]{0.0, 0.0, 0.0, Double.MIN_VALUE};
				gridBagLayout.rowWeights = new double[]{0.0, 0.0, Double.MIN_VALUE};
				frame.getContentPane().setLayout(gridBagLayout);
				
				JLabel lblNewLabel_1 = new JLabel(Strings.creditText);
				GridBagConstraints gbc_lblNewLabel_1 = new GridBagConstraints();
				gbc_lblNewLabel_1.fill = GridBagConstraints.BOTH;
				gbc_lblNewLabel_1.insets = new Insets(0, 0, 5, 5);
				gbc_lblNewLabel_1.gridx = 1;
				gbc_lblNewLabel_1.gridy = 0;
				frame.getContentPane().add(lblNewLabel_1, gbc_lblNewLabel_1);
				
				JLabel lblNewLabel = new JLabel(new ImageIcon(this.getClass().getClassLoader().getResource("logo_sm.png")));
				GridBagConstraints gbc_lblNewLabel = new GridBagConstraints();
				gbc_lblNewLabel.insets = new Insets(0, 0, 0, 5);
				gbc_lblNewLabel.gridx = 1;
				gbc_lblNewLabel.gridy = 1;
				frame.getContentPane().add(lblNewLabel, gbc_lblNewLabel);
			}
		});
		GridBagConstraints gbc_creditButton = new GridBagConstraints();
		gbc_creditButton.insets = new Insets(0, 0, 5, 0);
		gbc_creditButton.gridx = 2;
		gbc_creditButton.gridy = 0;
		add(creditButton, gbc_creditButton);
		

		jwtInputField = new JTextArea();
		jwtInputField.setRows(2);
		jwtInputField.setLineWrap(true);
		jwtInputField.setWrapStyleWord(true);

		GridBagConstraints gbc_jwtInputField = new GridBagConstraints();
		gbc_jwtInputField.insets = new Insets(0, 0, 5, 5);
		gbc_jwtInputField.fill = GridBagConstraints.BOTH;
		gbc_jwtInputField.gridx = 1;
		gbc_jwtInputField.gridy = 1;
		add(jwtInputField, gbc_jwtInputField);
		
		lblEnterSecret = new JLabel("Enter Secret / Key");
		lblEnterSecret.setFont(new Font("Tahoma", Font.BOLD, 12));
		GridBagConstraints gbc_lblEnterSecret = new GridBagConstraints();
		gbc_lblEnterSecret.anchor = GridBagConstraints.WEST;
		gbc_lblEnterSecret.insets = new Insets(0, 0, 5, 5);
		gbc_lblEnterSecret.gridx = 1;
		gbc_lblEnterSecret.gridy = 2;
		add(lblEnterSecret, gbc_lblEnterSecret);

		jwtKeyField = new JTextField();
		GridBagConstraints gbc_jwtKeyField = new GridBagConstraints();
		gbc_jwtKeyField.insets = new Insets(0, 0, 5, 5);
		gbc_jwtKeyField.fill = GridBagConstraints.HORIZONTAL;
		gbc_jwtKeyField.gridx = 1;
		gbc_jwtKeyField.gridy = 3;
		add(jwtKeyField, gbc_jwtKeyField);
		jwtKeyField.setColumns(10);

		jwtSignatureButton = new JButton("");
		Dimension preferredSize = new Dimension(400, 30);
		jwtSignatureButton.setPreferredSize(preferredSize);

		GridBagConstraints gbc_jwtSignatureButton = new GridBagConstraints();
		gbc_jwtSignatureButton.insets = new Insets(0, 0, 5, 5);
		gbc_jwtSignatureButton.gridx = 1;
		gbc_jwtSignatureButton.gridy = 5;
		add(jwtSignatureButton, gbc_jwtSignatureButton);

		GridBagConstraints gbc_jwtOuputField = new GridBagConstraints();
		gbc_jwtOuputField.insets = new Insets(0, 0, 5, 5);
		gbc_jwtOuputField.fill = GridBagConstraints.BOTH;
		gbc_jwtOuputField.gridx = 1;
		gbc_jwtOuputField.gridy = 7;

		jwtOuputField = new RSyntaxTextArea();
		SyntaxScheme scheme = jwtOuputField.getSyntaxScheme();
		Style style = new Style();
		style.foreground = new Color(222,133,10);
		scheme.setStyle(Token.LITERAL_STRING_DOUBLE_QUOTE, style);
		jwtOuputField.revalidate();
		jwtOuputField.setHighlightCurrentLine(false);
		jwtOuputField.setCurrentLineHighlightColor(Color.WHITE);
		jwtOuputField.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_JAVASCRIPT);
		jwtOuputField.setEditable(false);
		// no context menu on right-click
		jwtOuputField.setPopupMenu(new JPopupMenu()); 
		RTextScrollPane sp = new RTextScrollPane(jwtOuputField);
		sp.setLineNumbersEnabled(false);
		
		JLabel lblDecodedJwt = new JLabel(Strings.decodedJWT);
		lblDecodedJwt.setFont(new Font("Tahoma", Font.BOLD, 12));
		GridBagConstraints gbc_lblDecodedJwt = new GridBagConstraints();
		gbc_lblDecodedJwt.anchor = GridBagConstraints.WEST;
		gbc_lblDecodedJwt.insets = new Insets(0, 0, 5, 5);
		gbc_lblDecodedJwt.gridx = 1;
		gbc_lblDecodedJwt.gridy = 6;
		add(lblDecodedJwt, gbc_lblDecodedJwt);

		add(jwtOuputField, gbc_jwtOuputField);

	}
	
	public String getJWTInput(){
		return jwtInputField.getText();
	}
	
	public String getKeyInput(){
		return jwtKeyField.getText();
	}
}

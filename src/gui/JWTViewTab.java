package gui;

import java.awt.Color;
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

import org.fife.ui.rsyntaxtextarea.RSyntaxTextArea;
import org.fife.ui.rsyntaxtextarea.SyntaxConstants;
import org.fife.ui.rtextarea.RTextScrollPane;

import app.algorithm.AlgorithmType;
import app.helpers.Settings;
import model.JWTTabModel;

public class JWTViewTab extends JPanel{

	private static final long serialVersionUID = 1L;
	private RSyntaxTextArea  outputField;
	private JTextField keyField;
	private JLabel outputLabel;
	private JLabel keyLabel;
	private JButton verificationIndicator;
	private JLabel verificationLabel;
	private JWTTabModel jwtTM;

	public JWTViewTab(JWTTabModel jwtTM) {
		drawPanel();
		this.jwtTM = jwtTM;
	}

	public void registerDocumentListener(DocumentListener inputFieldListener) {
		keyField.getDocument().addDocumentListener(inputFieldListener);
	}

	
	private void drawPanel() {
		GridBagLayout gridBagLayout = new GridBagLayout();
		gridBagLayout.columnWidths = new int[] { 0, 79, 447, 0, 0 };
		gridBagLayout.rowHeights = new int[] { 0, 0, 0, 0, 0, 0, 0, 0, 0 };
		gridBagLayout.columnWeights = new double[] { 0.0, 0.0, 1.0, 0.0, Double.MIN_VALUE };
		gridBagLayout.rowWeights = new double[] { 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, Double.MIN_VALUE };
		setLayout(gridBagLayout);

		keyLabel = new JLabel("");
		GridBagConstraints gbc_inputLabel1 = new GridBagConstraints();
		gbc_inputLabel1.insets = new Insets(0, 0, 5, 5);
		gbc_inputLabel1.anchor = GridBagConstraints.EAST;
		gbc_inputLabel1.gridx = 1;
		gbc_inputLabel1.gridy = 1;
		add(keyLabel, gbc_inputLabel1);

		keyField = new JTextField();
		GridBagConstraints gbc_inputField1 = new GridBagConstraints();
		gbc_inputField1.insets = new Insets(0, 0, 5, 5);
		gbc_inputField1.fill = GridBagConstraints.HORIZONTAL;
		gbc_inputField1.gridx = 2;
		gbc_inputField1.gridy = 1;
		add(keyField, gbc_inputField1);
		keyField.setColumns(10);
		
		verificationLabel = new JLabel("");
		GridBagConstraints gbc_validIndicatorLabel = new GridBagConstraints();
		gbc_validIndicatorLabel.insets = new Insets(0, 0, 5, 5);
		gbc_validIndicatorLabel.gridx = 1;
		gbc_validIndicatorLabel.gridy = 3;
		add(verificationLabel, gbc_validIndicatorLabel);
		
		verificationIndicator = new JButton("                           ");
		GridBagConstraints gbc_validIndicator = new GridBagConstraints();
		gbc_validIndicator.insets = new Insets(0, 0, 5, 5);
		gbc_validIndicator.gridx = 2;
		gbc_validIndicator.gridy = 3;
		add(verificationIndicator, gbc_validIndicator);

		outputLabel = new JLabel("JWT");
		GridBagConstraints gbc_outputLabel = new GridBagConstraints();
		gbc_outputLabel.insets = new Insets(0, 0, 5, 5);
		gbc_outputLabel.gridx = 1;
		gbc_outputLabel.gridy = 5;
		add(outputLabel, gbc_outputLabel);

		outputField = new RSyntaxTextArea();
		outputField.setHighlightCurrentLine(false);
		outputField.setCurrentLineHighlightColor(Color.WHITE);
		outputField.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_JAVASCRIPT);
		outputField.setEditable(false);
		outputField.setPopupMenu(new JPopupMenu()); // no context menu on right-click
		RTextScrollPane sp = new RTextScrollPane(outputField);
		sp.setLineNumbersEnabled(false);
		
		GridBagConstraints gbc_outputfield = new GridBagConstraints();
		gbc_outputfield.insets = new Insets(0, 0, 5, 5);
		gbc_outputfield.fill = GridBagConstraints.BOTH;
		gbc_outputfield.gridx = 2;
		gbc_outputfield.gridy = 5;
		add(sp, gbc_outputfield);
	}
	
	public void updateToken() {
		//JWT token = jwtTabController.getJwtToken();
		//if (token == null) {
		//	outputField.setText(null);
		//} else {
		//	outputField.setText(jwtTabController.getFormatedToken());
		//}
	}
	
	public void updateAlgorithm(){
		//String algorithmType = AlgorithmLinker.getTypeOf(jwtTabController.getCurrentAlgorithm());
		String algorithmType ="TODO";
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
	}


//			int updateType = (int) arg; 
//			switch (updateType) {
//			case NotifyTypes.gui_algorithm:
//				updateAlgorithm();
//				break;
//			case NotifyTypes.gui_signaturecheck:
//				updateSignatureStatus();
//				break;
//			case NotifyTypes.gui_token:
//				updateToken();
//				setCaret();
//				break;
//			case NotifyTypes.all:
//				updateAlgorithm();
//				updateSignatureStatus();
//				updateToken();
//				setCaret();
//			default:
//				break;
//			}

	public JTextArea getOutputfield() {
		return outputField;
	}
	
	private void updateSignatureStatus() {
		//Color color = jwtTabController.getVerificationStatusColor();
		//validIndicatorLabel.setText("Signature "+jwtTabController.getVerificationResult());
		//validIndicator.setBackground(color);	
	}
	
	public String getKeyValue() {
		return keyField.getText();
	}

	public void setKeyValue(String value) {
		keyField.setText(value);		
	}

	public void setVerificationResult(String value) {
		verificationLabel.setText(value);
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

	public void updateSetView() {
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
				if(!jwtTM.getVerificationLabel().equals(verificationLabel.getText())){
					verificationLabel.setText(jwtTM.getVerificationLabel());
				}
				if(outputField.getText().equals("")){
					jwtTM.setVerificationColor(Settings.colorUndefined);
					verificationIndicator.setBackground(Settings.colorUndefined);
				}
				setCaret();
			}
		});
	}

}

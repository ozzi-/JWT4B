package gui;

import java.awt.Color;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.util.Observable;
import java.util.Observer;

import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPopupMenu;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

import org.fife.ui.rsyntaxtextarea.RSyntaxTextArea;
import org.fife.ui.rsyntaxtextarea.SyntaxConstants;
import org.fife.ui.rtextarea.RTextScrollPane;

import com.auth0.jwt.JWT;

import app.algorithm.AlgorithmLinker;
import app.algorithm.AlgorithmType;
import app.controllers.JWTMessageEditorTabController;
import app.helpers.NotifyTypes;

public class JWTViewTab extends JWTTab implements Observer {

	private static final long serialVersionUID = 1L;
	private RSyntaxTextArea  outputField;
	private JTextField inputField;
	private JLabel outputLabel;
	private JLabel inputLabel;
	private JWTMessageEditorTabController jwtTabController;
	private JButton validIndicator;
	private JLabel validIndicatorLabel;

	public JWTViewTab(JWTMessageEditorTabController visualizer) {
		this.jwtTabController = visualizer;
		jwtTabController.addObserver(this);
		drawPanel();
		registerDocumentListener();
	}

	private void registerDocumentListener() {
		inputField.getDocument().addDocumentListener(new DocumentListener() {
			public void changedUpdate(DocumentEvent e) {
				jwtTabController.checkKey(inputField.getText());
			}
			public void removeUpdate(DocumentEvent e) {
				jwtTabController.checkKey(inputField.getText());
			}
			public void insertUpdate(DocumentEvent e) {
				jwtTabController.checkKey(inputField.getText());
			}
		});
	}

	private void drawPanel() {
		GridBagLayout gridBagLayout = new GridBagLayout();
		gridBagLayout.columnWidths = new int[] { 0, 79, 447, 0, 0 };
		gridBagLayout.rowHeights = new int[] { 0, 0, 0, 0, 0, 0, 0, 0, 0 };
		gridBagLayout.columnWeights = new double[] { 0.0, 0.0, 1.0, 0.0, Double.MIN_VALUE };
		gridBagLayout.rowWeights = new double[] { 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, Double.MIN_VALUE };
		setLayout(gridBagLayout);

		inputLabel = new JLabel("");
		GridBagConstraints gbc_inputLabel1 = new GridBagConstraints();
		gbc_inputLabel1.insets = new Insets(0, 0, 5, 5);
		gbc_inputLabel1.anchor = GridBagConstraints.EAST;
		gbc_inputLabel1.gridx = 1;
		gbc_inputLabel1.gridy = 1;
		add(inputLabel, gbc_inputLabel1);

		inputField = new JTextField();
		GridBagConstraints gbc_inputField1 = new GridBagConstraints();
		gbc_inputField1.insets = new Insets(0, 0, 5, 5);
		gbc_inputField1.fill = GridBagConstraints.HORIZONTAL;
		gbc_inputField1.gridx = 2;
		gbc_inputField1.gridy = 1;
		add(inputField, gbc_inputField1);
		inputField.setColumns(10);
		
		validIndicatorLabel = new JLabel("");
		GridBagConstraints gbc_validIndicatorLabel = new GridBagConstraints();
		gbc_validIndicatorLabel.insets = new Insets(0, 0, 5, 5);
		gbc_validIndicatorLabel.gridx = 1;
		gbc_validIndicatorLabel.gridy = 3;
		add(validIndicatorLabel, gbc_validIndicatorLabel);
		
		validIndicator = new JButton("                           ");
		GridBagConstraints gbc_validIndicator = new GridBagConstraints();
		gbc_validIndicator.insets = new Insets(0, 0, 5, 5);
		gbc_validIndicator.gridx = 2;
		gbc_validIndicator.gridy = 3;
		add(validIndicator, gbc_validIndicator);

		outputLabel = new JLabel("JWT");
		GridBagConstraints gbc_outputLabel = new GridBagConstraints();
		gbc_outputLabel.insets = new Insets(0, 0, 5, 5);
		gbc_outputLabel.gridx = 1;
		gbc_outputLabel.gridy = 5;
		add(outputLabel, gbc_outputLabel);

		outputField = new RSyntaxTextArea();
		outputField.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_JAVASCRIPT);
		outputField.setEditable(false);
		outputField.setPopupMenu(new JPopupMenu()); // no context menu on right-click
		RTextScrollPane sp = new RTextScrollPane(outputField);
		
		GridBagConstraints gbc_outputfield = new GridBagConstraints();
		gbc_outputfield.insets = new Insets(0, 0, 5, 5);
		gbc_outputfield.fill = GridBagConstraints.BOTH;
		gbc_outputfield.gridx = 2;
		gbc_outputfield.gridy = 5;
		add(sp, gbc_outputfield);
	}
	
	public void updateToken() {
		JWT token = jwtTabController.getJwtToken();
		if (token == null) {
			outputField.setText(null);
		} else {
			outputField.setText(jwtTabController.getFormatedToken());
		}
	}
	
	public void updateAlgorithm(){
		String algorithmType = AlgorithmLinker.getTypeOf(jwtTabController.getCurrentAlgorithm());
		
		if(algorithmType.equals(AlgorithmType.symmetric)){
			inputLabel.setText("Secret");
			inputField.setEnabled(true);
		}
		if(algorithmType.equals(AlgorithmType.asymmetric)){
			inputLabel.setText("Public Key");
			inputField.setEnabled(true);
		}
		if(algorithmType.equals(AlgorithmType.none)){
			inputLabel.setText("");
			inputField.setEnabled(false);
			inputField.setEnabled(false);
		}
	}

	@Override
	public void update(Observable o, Object arg) {
		if(arg instanceof Integer){
			int updateType = (int) arg; 
			switch (updateType) {
			case NotifyTypes.gui_algorithm:
				updateAlgorithm();
				break;
			case NotifyTypes.gui_signaturecheck:
				updateSignatureStatus();
				break;
			case NotifyTypes.gui_token:
				updateToken();
				break;
			case NotifyTypes.all:
				updateAlgorithm();
				updateSignatureStatus();
				updateToken();
			default:
				break;
			}
		}
	}

	public JTextArea getOutputfield() {
		return outputField;
	}
	
	private void updateSignatureStatus() {
		Color color = jwtTabController.getVerificationStatusColor();
		validIndicatorLabel.setText("Signature "+jwtTabController.getVerificationResult());
		validIndicator.setBackground(color);	
	}
	
	public String getKeyValue() {
		return inputField.getText();
	}

	@Override
	public void setKeyValue(String value) {
		inputField.setText(value);		
	}

	@Override
	public void setVerificationResult(String value) {
		validIndicatorLabel.setText(value);
	}

	@Override
	public void setVerificationResultColor(Color verificationResultColor) {
		validIndicator.setBackground(verificationResultColor);
	}

}

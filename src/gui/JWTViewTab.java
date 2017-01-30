package gui;

import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.io.UnsupportedEncodingException;
import java.util.Observable;
import java.util.Observer;

import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.Verification;

import app.JWTMessageEditorTabController;

public class JWTViewTab extends JPanel implements Observer {

	private static final long serialVersionUID = 1L;
	private JTextField keyfield;

	private JTextArea outputfield;
	private JWTMessageEditorTabController jwtTabController;

	
	public JWTViewTab(JWTMessageEditorTabController visualizer) {
		
		this.jwtTabController = visualizer;
		jwtTabController.addObserver(this);
		
		drawPanel();
		registerDocumentListener();
	}

	private void registerDocumentListener() {
		keyfield.getDocument().addDocumentListener(new DocumentListener() {
			public void changedUpdate(DocumentEvent e) {
				jwtTabController.checkKey(keyfield.getText());
			}
			public void removeUpdate(DocumentEvent e) {
				jwtTabController.checkKey(keyfield.getText());
			}
			public void insertUpdate(DocumentEvent e) {
				jwtTabController.checkKey(keyfield.getText());
			}
		});
	}

	private void drawPanel() {
		GridBagLayout gridBagLayout = new GridBagLayout();
		gridBagLayout.columnWidths = new int[] { 0, 447, 0, 0 };
		gridBagLayout.rowHeights = new int[] { 0, 0, 0, 0, 0, 0 };
		gridBagLayout.columnWeights = new double[] { 0.0, 1.0, 0.0, Double.MIN_VALUE };
		gridBagLayout.rowWeights = new double[] { 0.0, 0.0, 0.0, 1.0, 0.0, Double.MIN_VALUE };
		setLayout(gridBagLayout);

		keyfield = new JTextField();
		keyfield.setToolTipText("Enter Key");
		GridBagConstraints gbc_keyfield = new GridBagConstraints();
		gbc_keyfield.insets = new Insets(0, 0, 5, 5);
		gbc_keyfield.fill = GridBagConstraints.HORIZONTAL;
		gbc_keyfield.gridx = 1;
		gbc_keyfield.gridy = 1;
		add(keyfield, gbc_keyfield);
		keyfield.setColumns(10);
		
		outputfield = new JTextArea();
		GridBagConstraints gbc_outputfield = new GridBagConstraints();
		gbc_outputfield.insets = new Insets(0, 0, 5, 5);
		gbc_outputfield.fill = GridBagConstraints.BOTH;
		gbc_outputfield.gridx = 1;
		gbc_outputfield.gridy = 3;
		add(outputfield, gbc_outputfield);
	}
	
	public void updateToken() { 
		JWT token = jwtTabController.getJwtToken();
		if (token == null) {
			getOutputfield().setText(null);
			getOutputfield().setEditable(false);
		} else {
			getOutputfield().setText(jwtTabController.getFormatedToken());
			getOutputfield().setEditable(true);
		}
	}
	
	private JTextArea getOutputfield() { 
		return this.outputfield;
	}


	@Override
	public void update(Observable o, Object arg) {
		updateToken();
	}




}

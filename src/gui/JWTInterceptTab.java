package gui;

import java.awt.Color;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;

import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JRadioButton;
import javax.swing.JSeparator;
import javax.swing.SwingConstants;
import javax.swing.SwingUtilities;

import org.fife.ui.rsyntaxtextarea.RSyntaxTextArea;
import org.fife.ui.rsyntaxtextarea.Style;
import org.fife.ui.rsyntaxtextarea.SyntaxConstants;
import org.fife.ui.rsyntaxtextarea.SyntaxScheme;
import org.fife.ui.rsyntaxtextarea.Token;
import org.fife.ui.rtextarea.RTextScrollPane;

import app.helpers.ConsoleOut;
import model.JWTInterceptModel;

public class JWTInterceptTab extends JPanel {

	private static final long serialVersionUID = 1L;
	private JWTInterceptModel jwtIM;
	private RSyntaxTextArea textArea;

	public JWTInterceptTab(JWTInterceptModel jwtIM) {
		this.jwtIM = jwtIM;
		drawGui();
	}
	
	private void drawGui() {	
		GridBagLayout gridBagLayout = new GridBagLayout();
		gridBagLayout.columnWidths = new int[]{0, 0, 0};
		gridBagLayout.rowHeights = new int[]{0, 0, 0, 0, 0, 0};
		gridBagLayout.columnWeights = new double[]{1.0, 1.0, Double.MIN_VALUE};
		gridBagLayout.rowWeights = new double[]{0.0, 0.0, 0.0, 0.0, 0.0, Double.MIN_VALUE};
		setLayout(gridBagLayout);
		
		textArea = new RSyntaxTextArea ();
		SyntaxScheme scheme = textArea.getSyntaxScheme();
		Style style = new Style();
		style.foreground = new Color(222,133,10);
		scheme.setStyle(Token.LITERAL_STRING_DOUBLE_QUOTE, style);
		textArea.revalidate();
		textArea.setHighlightCurrentLine(false);
		textArea.setCurrentLineHighlightColor(Color.WHITE);
		textArea.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_JAVASCRIPT);
		textArea.setEditable(true);
		textArea.setPopupMenu(new JPopupMenu()); 
		RTextScrollPane sp = new RTextScrollPane(textArea);
		sp.setLineNumbersEnabled(false);
		
		GridBagConstraints gbc_textArea = new GridBagConstraints();
		gbc_textArea.gridheight = 5;
		gbc_textArea.insets = new Insets(0, 0, 0, 5);
		gbc_textArea.fill = GridBagConstraints.BOTH;
		gbc_textArea.gridx = 0;
		gbc_textArea.gridy = 0;
		add(textArea, gbc_textArea);
		
		JRadioButton rdbtnRecalculateSignature = new JRadioButton("Recalculate signature");
		rdbtnRecalculateSignature.setHorizontalAlignment(SwingConstants.LEFT);
		GridBagConstraints gbc_rdbtnRecalculateSignature = new GridBagConstraints();
		gbc_rdbtnRecalculateSignature.anchor = GridBagConstraints.WEST;
		gbc_rdbtnRecalculateSignature.insets = new Insets(0, 0, 5, 0);
		gbc_rdbtnRecalculateSignature.gridx = 1;
		gbc_rdbtnRecalculateSignature.gridy = 0;
		add(rdbtnRecalculateSignature, gbc_rdbtnRecalculateSignature);
		
		JRadioButton rdbtnNewRadioButton = new JRadioButton("Sign with random key pair");
		rdbtnNewRadioButton.setHorizontalAlignment(SwingConstants.LEFT);
		GridBagConstraints gbc_rdbtnNewRadioButton = new GridBagConstraints();
		gbc_rdbtnNewRadioButton.anchor = GridBagConstraints.WEST;
		gbc_rdbtnNewRadioButton.insets = new Insets(0, 0, 5, 0);
		gbc_rdbtnNewRadioButton.gridx = 1;
		gbc_rdbtnNewRadioButton.gridy = 1;
		add(rdbtnNewRadioButton, gbc_rdbtnNewRadioButton);
		
		JRadioButton rdbtnNewRadioButton_1 = new JRadioButton("Keep original signature");
		rdbtnNewRadioButton_1.setHorizontalAlignment(SwingConstants.LEFT);
		GridBagConstraints gbc_rdbtnNewRadioButton_1 = new GridBagConstraints();
		gbc_rdbtnNewRadioButton_1.insets = new Insets(0, 0, 5, 0);
		gbc_rdbtnNewRadioButton_1.anchor = GridBagConstraints.WEST;
		gbc_rdbtnNewRadioButton_1.gridx = 1;
		gbc_rdbtnNewRadioButton_1.gridy = 2;
		add(rdbtnNewRadioButton_1, gbc_rdbtnNewRadioButton_1);
		
		JSeparator separator = new JSeparator();
		GridBagConstraints gbc_separator = new GridBagConstraints();
		gbc_separator.insets = new Insets(0, 0, 5, 0);
		gbc_separator.gridx = 1;
		gbc_separator.gridy = 3;
		add(separator, gbc_separator);
		
		JLabel lblTodoAutomated = new JLabel("Todo : Automated Attacks");
		GridBagConstraints gbc_lblTodoAutomated = new GridBagConstraints();
		gbc_lblTodoAutomated.gridx = 1;
		gbc_lblTodoAutomated.gridy = 4;
		add(lblTodoAutomated, gbc_lblTodoAutomated);
	}

	public void updateSetView() {
		SwingUtilities.invokeLater(new Runnable() {
			public void run() {
				if(!textArea.getText().equals(jwtIM.getJWTJSON())){
					textArea.setText(jwtIM.getJWTJSON());					
				}
			}
		});
	}

}

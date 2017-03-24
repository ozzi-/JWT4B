package gui;

import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.util.Observable;
import java.util.Observer;

import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextArea;
import javax.swing.JTextPane;
import javax.swing.SwingConstants;

import app.algorithm.AlgorithmLinker;
import app.algorithm.AlgorithmType;
import app.algorithm.AlgorithmWrapper;
import app.controllers.JWTTabController;
import app.helpers.Strings;

public class JWTEditableTab extends JPanel implements Observer {

	private static final long serialVersionUID = 1L;
	private JWTTabController messageEditorTabController;
	private JTextPane textPaneTokenEditor;
	private JTextArea textFieldInputKey;
	private JCheckBox chckbxRecalculateSignature;
	private JButton btnChangeAlgorithm;
	JComboBox<String> comboBoxAlgorithmSelection;
	private JButton btnAcceptChanges;
	private JLabel lblState;
	private JButton btnGenerateRandomKey;

	public JWTEditableTab(JWTTabController messageEditorTabController) {
		this.messageEditorTabController = messageEditorTabController;
		//messageEditorTabController.addObserver(this); 
		drawGui(messageEditorTabController);
	}

	private void drawGui(JWTTabController messageEditorTabController) {
		this.messageEditorTabController = messageEditorTabController;
		GridBagLayout gridBagLayout = new GridBagLayout();
		gridBagLayout.columnWidths = new int[]{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
		gridBagLayout.rowHeights = new int[]{0, 0, 0};
		gridBagLayout.columnWeights = new double[]{0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
				0.0, 0.0, 1.0, Double.MIN_VALUE};
		gridBagLayout.rowWeights = new double[]{0.0, 1.0, Double.MIN_VALUE};
		setLayout(gridBagLayout);

		btnAcceptChanges = new JButton(Strings.acceptChanges);
		// TODO btnAcceptChanges.addActionListener(e -> messageEditorTabController.setChangedToken(textPaneTokenEditor.getText()));
		GridBagConstraints gbc_btnAcceptChanges = new GridBagConstraints();
		gbc_btnAcceptChanges.insets = new Insets(0, 0, 5, 5);
		gbc_btnAcceptChanges.gridx = 2;
		gbc_btnAcceptChanges.gridy = 0;
		add(btnAcceptChanges, gbc_btnAcceptChanges);

		lblState = new JLabel(Strings.originalToken);
		GridBagConstraints gbc_lblOriginalToken = new GridBagConstraints();
		gbc_lblOriginalToken.insets = new Insets(0, 0, 5, 5);
		gbc_lblOriginalToken.gridx = 3;
		gbc_lblOriginalToken.gridy = 0;
		add(lblState, gbc_lblOriginalToken);

		textPaneTokenEditor = new JTextPane();
		GridBagConstraints gbc_textPane = new GridBagConstraints();
		gbc_textPane.gridwidth = 13;
		gbc_textPane.insets = new Insets(0, 0, 0, 5);
		gbc_textPane.fill = GridBagConstraints.BOTH;
		gbc_textPane.gridx = 1;
		gbc_textPane.gridy = 1;
		add(textPaneTokenEditor, gbc_textPane);

		JPanel panel = new JPanel();
		FlowLayout flowLayout = (FlowLayout) panel.getLayout();
		flowLayout.setAlignment(FlowLayout.LEFT);
		GridBagConstraints gbc_panel = new GridBagConstraints();
		gbc_panel.fill = GridBagConstraints.VERTICAL;
		gbc_panel.gridx = 15;
		gbc_panel.gridy = 1;
		add(panel, gbc_panel);

		comboBoxAlgorithmSelection = new JComboBox<>();
		for (AlgorithmWrapper algorithm : AlgorithmLinker.getSupportedAlgorithms()) {
			comboBoxAlgorithmSelection.addItem(algorithm.getAlgorithm());
		}
		comboBoxAlgorithmSelection.addItemListener(e -> {
			updateKeyFieldsAccordingToTheOtherTwoUiFieldsBefore();
		});

		panel.add(comboBoxAlgorithmSelection);

		chckbxRecalculateSignature = new JCheckBox(Strings.recalculateSignature);
		chckbxRecalculateSignature.addChangeListener(
				e -> {
					updateKeyFieldsAccordingToTheOtherTwoUiFieldsBefore();
				});

		panel.add(chckbxRecalculateSignature);

		textFieldInputKey = new JTextArea("");
		panel.add(textFieldInputKey);
		textFieldInputKey.setColumns(27);
		textFieldInputKey.setRows(27);


		btnChangeAlgorithm = new JButton(Strings.updateAlgorithmSignature);
		btnChangeAlgorithm.setVerticalAlignment(SwingConstants.TOP);
		panel.add(btnChangeAlgorithm);
		btnChangeAlgorithm.setEnabled(true);
		btnChangeAlgorithm.addActionListener(e -> {
			String algorithm = comboBoxAlgorithmSelection.getSelectedItem().toString();
			Boolean recalculateSignature = chckbxRecalculateSignature.isSelected();
			String signatureKey = textFieldInputKey.getText();
			//messageEditorTabController.changeAlgorithm(algorithm, recalculateSignature, signatureKey);
		});

		btnGenerateRandomKey = new JButton("Generate Random Key");
		btnGenerateRandomKey.setVerticalAlignment(SwingConstants.TOP);
		panel.add(btnGenerateRandomKey);
		btnGenerateRandomKey.setEnabled(false);
		btnGenerateRandomKey.addActionListener(e -> {
			//String key = this.messageEditorTabController.generateKeyPair();
			//this.textFieldInputKey.setText(key);
		});
	}

	private void updateKeyFieldsAccordingToTheOtherTwoUiFieldsBefore() {
		String algorithmType = AlgorithmLinker.getTypeOf(getSelectedAlgorithm());

		if (algorithmType.equals(AlgorithmType.asymmetric)) {
			this.btnGenerateRandomKey.setEnabled(true);
		} else {
			this.btnGenerateRandomKey.setEnabled(false);
		}

		if (algorithmType.equals(AlgorithmType.none) || !chckbxRecalculateSignature.isSelected()) {
			textFieldInputKey.setEnabled(false);
			return;
		}

		textFieldInputKey.setEnabled(true);
	}

	@Override
	public void update(Observable o, Object arg) {
		updateView();
	}

	private void updateView() {
		// TODO String formattedToken = messageEditorTabController.getFormatedToken();
		// this.textPaneTokenEditor.setText(formattedToken);

		comboBoxAlgorithmSelection.setSelectedItem(this.messageEditorTabController.getCurrentAlgorithm());
		chckbxRecalculateSignature.setSelected(false);
		chckbxRecalculateSignature.setEnabled(true);
		textFieldInputKey.setEnabled(chckbxRecalculateSignature.isSelected());
		btnChangeAlgorithm.setEnabled(true);

		this.lblState.setText(this.messageEditorTabController.getState());
		// this.lblState.setForeground(this.messageEditorTabController.getVerificationStatusColor());
	}

	public String getSelectedAlgorithm() {
		if (this.comboBoxAlgorithmSelection.getSelectedItem() == null) {
			return "";
		}
		return this.comboBoxAlgorithmSelection.getSelectedItem().toString();
	}
	
	public JTextPane getTextPaneTokenEditor() {
		return textPaneTokenEditor;
	}

	public String getKeyValue() {
		return textFieldInputKey.getText();
	}

	public void setKeyValue(String value) {
		textFieldInputKey.setText(value);
	}

	public String getSelectedData() {
		return getTextPaneTokenEditor().getSelectedText();
	}

}

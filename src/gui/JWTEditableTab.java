package gui;

import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.util.Observable;
import java.util.Observer;

import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.JTextPane;
import javax.swing.SwingConstants;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import app.JWTMessageEditorTabController;
import app.algorithm.AlgorithmWrapper;
import app.algorithm.AlgorithmLinker;

public class JWTEditableTab extends JPanel implements Observer {

	private static final long serialVersionUID = 1L;
	private JWTMessageEditorTabController messageEditorTabController;
	private JTextPane textPaneTokenEditor;
	private JTextField textFieldInputKey;
	private JCheckBox chckbxRecalculateSignature;
	private JButton btnChangeAlgorithm;
	JComboBox<String> comboBoxAlgorithmSelection;
	private JButton btnAcceptChanges;
	private JLabel lblState;

	public JWTEditableTab(JWTMessageEditorTabController messageEditorTabController) {

		this.messageEditorTabController = messageEditorTabController;
		messageEditorTabController.addObserver(this);

		drawGui(messageEditorTabController);
	}

	private void drawGui(JWTMessageEditorTabController messageEditorTabController) {
		this.messageEditorTabController = messageEditorTabController;
		GridBagLayout gridBagLayout = new GridBagLayout();
		gridBagLayout.columnWidths = new int[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
		gridBagLayout.rowHeights = new int[] { 0, 0, 0 };
		gridBagLayout.columnWeights = new double[] { 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
				0.0, 0.0, 1.0, Double.MIN_VALUE };
		gridBagLayout.rowWeights = new double[] { 0.0, 1.0, Double.MIN_VALUE };
		setLayout(gridBagLayout);

		btnAcceptChanges = new JButton("Accept Changes");
		btnAcceptChanges.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				messageEditorTabController.setChangedToken(textPaneTokenEditor.getText());
			}
		});
		GridBagConstraints gbc_btnAcceptChanges = new GridBagConstraints();
		gbc_btnAcceptChanges.insets = new Insets(0, 0, 5, 5);
		gbc_btnAcceptChanges.gridx = 2;
		gbc_btnAcceptChanges.gridy = 0;
		add(btnAcceptChanges, gbc_btnAcceptChanges);

		lblState = new JLabel("Original Token");
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
		comboBoxAlgorithmSelection.addItemListener(new ItemListener() {
			public void itemStateChanged(ItemEvent e) {
				Boolean algorithmChanged = hasAlgorithmChanged();

				btnChangeAlgorithm.setEnabled(algorithmChanged);
				chckbxRecalculateSignature.setEnabled(algorithmChanged);

			}

		});

		panel.add(comboBoxAlgorithmSelection);

		chckbxRecalculateSignature = new JCheckBox("Recalculate Signature");
		chckbxRecalculateSignature.addChangeListener(new ChangeListener() {

			public void stateChanged(ChangeEvent e) {
				Boolean signatureIsRecalculated = chckbxRecalculateSignature.isSelected();
				textFieldInputKey.setEnabled(
						signatureIsRecalculated && !messageEditorTabController.getCurrentAlgorithm().equals("none"));
			}

		});
		panel.add(chckbxRecalculateSignature);

		textFieldInputKey = new JTextField();
		panel.add(textFieldInputKey);
		textFieldInputKey.setColumns(10);

		btnChangeAlgorithm = new JButton("Change Algorithm");
		btnChangeAlgorithm.setVerticalAlignment(SwingConstants.TOP);
		panel.add(btnChangeAlgorithm);
		btnChangeAlgorithm.setEnabled(false);
		btnChangeAlgorithm.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				String algorithm = comboBoxAlgorithmSelection.getSelectedItem().toString();
				Boolean recalculateSignature = chckbxRecalculateSignature.isSelected();
				String signatureKey = textFieldInputKey.getText();
				messageEditorTabController.changeAlgorithm(algorithm, recalculateSignature, signatureKey);
			}
		});
	}

	@Override
	public void update(Observable o, Object arg) {
		updateView();
	}

	private void updateView() {
		String formattedToken = messageEditorTabController.getFormatedToken();
		this.textPaneTokenEditor.setText(formattedToken);

		if (hasAlgorithmChanged()) {
			comboBoxAlgorithmSelection.setSelectedItem(this.messageEditorTabController.getCurrentAlgorithm());
			chckbxRecalculateSignature.setSelected(false);
			chckbxRecalculateSignature.setEnabled(false);
			textFieldInputKey.setEnabled(false);
			btnChangeAlgorithm.setEnabled(false);
		}

		this.lblState.setText(this.messageEditorTabController.getState());
		this.lblState.setForeground(this.messageEditorTabController.getVerificationStatusColor());
	}

	private Boolean hasAlgorithmChanged() {
		if (this.comboBoxAlgorithmSelection.getSelectedItem() == null) {
			return false;
		}
		return !this.comboBoxAlgorithmSelection.getSelectedItem().toString()
				.equals(messageEditorTabController.getCurrentAlgorithm());
	}
}

package gui;

import java.util.Observable;
import java.util.Observer;

import javax.swing.JPanel;

import javax.swing.JButton;
import java.awt.CardLayout;
import java.awt.GridBagLayout;
import java.awt.GridBagConstraints;
import javax.swing.JTextPane;

import com.auth0.jwt.JWT;

import app.JWTMessageEditorTabController;

import java.awt.Insets;
import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;

public class JWTEditableTab extends JPanel implements Observer{
	
	private JWTMessageEditorTabController messageEditorTabController;
	private JTextPane textPaneTokenEditor;

	public JWTEditableTab(JWTMessageEditorTabController messageEditorTabController) {
		
		this.messageEditorTabController = messageEditorTabController;
		messageEditorTabController.addObserver(this);
		
		drawGui(messageEditorTabController);
	}

	private void drawGui(JWTMessageEditorTabController messageEditorTabController) {
		this.messageEditorTabController = messageEditorTabController;
		GridBagLayout gridBagLayout = new GridBagLayout();
		gridBagLayout.columnWidths = new int[]{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
		gridBagLayout.rowHeights = new int[]{0, 0, 0};
		gridBagLayout.columnWeights = new double[]{0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, Double.MIN_VALUE};
		gridBagLayout.rowWeights = new double[]{0.0, 1.0, Double.MIN_VALUE};
		setLayout(gridBagLayout);
		
		JButton btnNonealgorithm = new JButton("None-Algorithm");
		btnNonealgorithm.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				messageEditorTabController.changeSingatureAlgorithmToNone();
			}
		});
		GridBagConstraints gbc_btnNonealgorithm = new GridBagConstraints();
		gbc_btnNonealgorithm.insets = new Insets(0, 0, 5, 0);
		gbc_btnNonealgorithm.gridx = 15;
		gbc_btnNonealgorithm.gridy = 0;
		add(btnNonealgorithm, gbc_btnNonealgorithm);
		
		textPaneTokenEditor = new JTextPane();
		GridBagConstraints gbc_textPane = new GridBagConstraints();
		gbc_textPane.gridwidth = 13;
		gbc_textPane.insets = new Insets(0, 0, 0, 5);
		gbc_textPane.fill = GridBagConstraints.BOTH;
		gbc_textPane.gridx = 1;
		gbc_textPane.gridy = 1;
		add(textPaneTokenEditor, gbc_textPane);
	}

	@Override
	public void update(Observable o, Object arg) {
		updateView();
	}
	
	private void updateView() { 
		String formattedToken = messageEditorTabController.getFormatedToken();
		this.textPaneTokenEditor.setText(formattedToken);
	}

}

package app.helpers;

import java.awt.Cursor;
/**
 * Example of a jLabel Hyperlink and a jLabel Mailto
 */
import java.awt.Desktop;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.net.URI;

import javax.swing.BoxLayout;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.border.EmptyBorder;

public class JLabelLink extends JFrame {

	private static final long serialVersionUID = 1L;
	private JPanel pan;

	public JLabelLink(String title, int x, int y) {
		this.setTitle(title);
		this.setSize(x,y);
		this.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
		this.setBounds(0, 0, x,y);
		this.setLocationRelativeTo(null);
		this.setLocationRelativeTo(null);

		pan = new JPanel();
		pan.setBorder(new EmptyBorder(10, 10, 10, 10));
		BoxLayout boxLayout = new BoxLayout(pan, BoxLayout.Y_AXIS);
		pan.setLayout(boxLayout);

		this.setContentPane(pan);
		this.setVisible(true);

	}

	public void addURL(String content, String tooltip) {
		JLabel label = new JLabel("<html>"+content+"</html>");
		label.setCursor(new Cursor(Cursor.HAND_CURSOR));
		label.setToolTipText(tooltip);
		addMouseHandler(label);
		pan.add(label);
	}

	public void addText(String content) {
		JLabel label = new JLabel("<html>"+content+"</html>");
		pan.add(label);
	}

	public void addRemoteImage(String string) {
		JLabel label = new JLabel("<html><img src=\""+string+"\"></html>");
		pan.add(label);
	}
	
	private void addMouseHandler(final JLabel website) {
		website.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				try {
					Desktop.getDesktop().browse(
							new URI(parseHREF(website.getText())));
				} catch (Exception ex) {
				}
			}
		});
	}

	private static String parseHREF(String html) {
		String hrefMarker = "href=\"";
		int hrefLoc = html.indexOf(hrefMarker);
		if (hrefLoc > 1) {
			int hrefEndLoc = html.indexOf("\">");
			if (hrefEndLoc > hrefLoc + 4) {
				return html
						.substring(hrefLoc + hrefMarker.length(), hrefEndLoc);
			}
		}
		return null;
	}


}
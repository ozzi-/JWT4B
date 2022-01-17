package gui;

import java.awt.Cursor;
import java.awt.Desktop;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URI;
import java.util.Base64;
import java.util.Objects;

import javax.imageio.ImageIO;
import javax.swing.BoxLayout;
import javax.swing.ImageIcon;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.border.EmptyBorder;

import app.helpers.Output;

public class JLabelLink extends JFrame {
  private static final String LOGO_DATA = "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";
  private static final Base64.Decoder DECODER = Base64.getDecoder();
  private static final long serialVersionUID = 1L;
  private final JPanel pan;

  public JLabelLink(String title, int x, int y) {
    this.setTitle(title);
    this.setSize(x, y);
    this.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
    this.setBounds(0, 0, x, y);
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
    JLabel label = new JLabel("<html>" + content + "</html>");
    label.setCursor(new Cursor(Cursor.HAND_CURSOR));
    label.setToolTipText(tooltip);
    addMouseHandler(label);
    pan.add(label);
  }

  public void addText(String content) {
    JLabel label = new JLabel("<html>" + content + "</html>");
    pan.add(label);
  }

  public void addLogoImage() {
    byte[] imageBytes = DECODER.decode(LOGO_DATA);
    try {
      BufferedImage img = ImageIO.read(new ByteArrayInputStream(imageBytes));
      ImageIcon icon = new ImageIcon(img);
      JLabel label = new JLabel();
      label.setIcon(icon);
      pan.add(label);
    } catch (IOException e) {
      e.printStackTrace();
    }
  }

  private void addMouseHandler(final JLabel website) {
    website.addMouseListener(new MouseAdapter() {

      @Override
      public void mouseClicked(MouseEvent e) {
        try {
          String href = parseHREF(website.getText());
          Desktop.getDesktop().browse(new URI(Objects.requireNonNull(href)));
        } catch (Exception ex) {
          Output.outputError("Exception trying to browser from jlabel href - "+ex.getMessage());
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
        return html.substring(hrefLoc + hrefMarker.length(), hrefEndLoc);
      }
    }
    return null;
  }

}

package app.helpers;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.Timer;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

// Source: https://raw.githubusercontent.com/bonifaido/JIT-Tree/master/src/main/java/me/nandork/jittree/DelayedDocumentListener.java
// License: MIT (https://opensource.org/licenses/MIT)

public class DelayedDocumentListener implements DocumentListener {

  public static final int DELAY = 400;

  private final Timer timer;
  private DocumentEvent lastEvent;

  public DelayedDocumentListener(DocumentListener delegate) {
    this(delegate, DELAY);
  }

  public DelayedDocumentListener(final DocumentListener delegate, int delay) {
    timer = new Timer(delay, new ActionListener() {

      @Override
      public void actionPerformed(ActionEvent e) {
        timer.stop();
        fireLastEventOn(delegate);
      }
    });
  }

  private void fireLastEventOn(DocumentListener delegate) {
    if (lastEvent.getType() == DocumentEvent.EventType.INSERT) {
      delegate.insertUpdate(lastEvent);
    } else if (lastEvent.getType() == DocumentEvent.EventType.REMOVE) {
      delegate.removeUpdate(lastEvent);
    } else {
      delegate.changedUpdate(lastEvent);
    }
  }

  private void storeUpdate(DocumentEvent e) {
    lastEvent = e;
    timer.restart();
  }

  @Override
  public void insertUpdate(DocumentEvent e) {
    storeUpdate(e);
  }

  @Override
  public void removeUpdate(DocumentEvent e) {
    storeUpdate(e);
  }

  @Override
  public void changedUpdate(DocumentEvent e) {
    storeUpdate(e);
  }
}
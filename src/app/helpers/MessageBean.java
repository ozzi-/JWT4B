package app.helpers;

import java.beans.PropertyChangeListener;
import java.beans.PropertyChangeSupport;

public class MessageBean {

    private String message; // the bean  property
    private final PropertyChangeSupport support = new PropertyChangeSupport(this);

    public void addPropertyChangeListener(PropertyChangeListener listener) {
        support.addPropertyChangeListener(listener);
    }

    public void removePropertyChangeListener(PropertyChangeListener listener) {
        support.removePropertyChangeListener(listener);
    }

    public String getMessage() {
        return this.message;
    }

    public void setMessage(String newValue) {
        String oldValue = this.message;
        this.message = newValue;
        // The parameter values of firePropertyChange method
        // constitute the PropertyChangeEvent object
        support.firePropertyChange("message", oldValue, newValue);
    }
}
package burp;

import app.JWTMessageEditorTabController;
import app.JWTSuiteTabController;
import app.Settings;
import gui.JWTEditableTab;
import gui.JWTViewTab;

public class BurpExtender implements IBurpExtender, IMessageEditorTabFactory {
	private IBurpExtenderCallbacks callbacks;
	
	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
		this.callbacks = callbacks;
		callbacks.setExtensionName(Settings.extensionName);
		callbacks.registerMessageEditorTabFactory(this);
		JWTSuiteTabController jstC = new JWTSuiteTabController();
		callbacks.addSuiteTab(jstC);
	}

	@Override
	public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
		JWTMessageEditorTabController visualizer = new JWTMessageEditorTabController(callbacks);
		if (editable) {
			visualizer.addTab(new JWTEditableTab(visualizer));
		} else {
			visualizer.addTab(new JWTViewTab(visualizer));
		}
		return visualizer;
	}
	
	public IBurpExtenderCallbacks getCallbacks() {
		return callbacks;
	}
}

package burp;

import app.controllers.ContextMenuController;
import app.controllers.JWTSuiteTabController;
import app.controllers.JWTTabController;
import app.helpers.Settings;
import gui.JWTSuiteTab;
import gui.JWTViewTab;
import model.JWTSuiteTabModel;
import model.JWTTabModel;

public class BurpExtender implements IBurpExtender, IMessageEditorTabFactory {
	private IBurpExtenderCallbacks callbacks;

	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
		this.callbacks = callbacks;
		callbacks.setExtensionName(Settings.extensionName);
		callbacks.registerMessageEditorTabFactory(this);
		// Suite Tab
		JWTSuiteTabModel jwtSTM =  new JWTSuiteTabModel();
		JWTSuiteTab jwtST = new JWTSuiteTab(jwtSTM);
		JWTSuiteTabController jstC = new JWTSuiteTabController(jwtSTM, jwtST);
		callbacks.addSuiteTab(jstC);
		// Context Menu
		ContextMenuController cmC = new ContextMenuController(jstC);
		callbacks.registerContextMenuFactory(cmC);
	}

	@Override
	public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
		if (editable) { // Intercept
		} else {
			// TODO workaround until editable / intercept view is rewritten with MVC and refactored
		}
		JWTTabModel jwtTM = new JWTTabModel();
		JWTViewTab jwtVT = new JWTViewTab(jwtTM);
		JWTTabController visualizer = new JWTTabController(callbacks,jwtTM,jwtVT);
		visualizer.addTab(jwtVT);
		return visualizer;
	}
	
	public IBurpExtenderCallbacks getCallbacks() {
		return callbacks;
	}
}

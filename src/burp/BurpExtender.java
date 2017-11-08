package burp;

import gui.JWTInterceptTab;
import gui.JWTSuiteTab;
import gui.JWTViewTab;

import java.io.PrintWriter;

import model.JWTInterceptModel;
import model.JWTSuiteTabModel;
import model.JWTTabModel;
import app.controllers.ContextMenuController;
import app.controllers.HighLightController;
import app.controllers.JWTInterceptTabController;
import app.controllers.JWTSuiteTabController;
import app.controllers.JWTTabController;
import app.helpers.Settings;

public class BurpExtender implements IBurpExtender, IMessageEditorTabFactory {
	private IBurpExtenderCallbacks callbacks;

	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
		this.callbacks = callbacks;
		PrintWriter stdout = new PrintWriter(callbacks.getStdout(), true);
		stdout.println("JWT4B says hi!");
		
		callbacks.setExtensionName(Settings.extensionName);
		callbacks.registerMessageEditorTabFactory(this);
		
		final HighLightController marker = new HighLightController(callbacks);
        callbacks.registerHttpListener(marker);

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
		IMessageEditorTab jwtTC;
		if (editable) { // Intercept
			JWTInterceptModel jwtSTM = new JWTInterceptModel();
			JWTInterceptTab jwtST = new JWTInterceptTab(jwtSTM);
			jwtTC = (IMessageEditorTab) new JWTInterceptTabController(callbacks,jwtSTM, jwtST);
		} else {
			JWTTabModel jwtTM = new JWTTabModel();
			JWTViewTab jwtVT = new JWTViewTab(jwtTM);
			jwtTC = new JWTTabController(callbacks,jwtTM,jwtVT);
		}
		return jwtTC;
	}
	
	public IBurpExtenderCallbacks getCallbacks() {
		return callbacks;
	}
}

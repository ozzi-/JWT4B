package burp;

import burp.api.montoya.ui.editor.extension.*;

import app.controllers.JWTRequestTabController;
import app.controllers.JWTResponseTabController;
import app.controllers.JWTRequestInterceptTabController;
import app.controllers.JWTResponseInterceptTabController;
import gui.JWTInterceptTab;
import gui.JWTViewTab;
import gui.RSyntaxTextAreaFactory;
import model.JWTInterceptModel;
import model.JWTTabModel;

public class JWT4BEditorProvider implements HttpRequestEditorProvider, HttpResponseEditorProvider {
	private final RSyntaxTextAreaFactory rSyntaxTextAreaFactory;

	public JWT4BEditorProvider(RSyntaxTextAreaFactory rSyntaxTextAreaFactory) {
		this.rSyntaxTextAreaFactory = rSyntaxTextAreaFactory;
	}

	@Override
	public ExtensionProvidedHttpRequestEditor provideHttpRequestEditor(EditorCreationContext creationContext) {
		ExtensionProvidedHttpRequestEditor jwtTC;

		if (creationContext.editorMode() == EditorMode.DEFAULT) {
			JWTInterceptModel jwtSTM = new JWTInterceptModel();
			JWTInterceptTab jwtST = new JWTInterceptTab(jwtSTM, rSyntaxTextAreaFactory);
			jwtTC = new JWTRequestInterceptTabController(jwtSTM, jwtST);
		} else {
			// Read Only
			JWTTabModel jwtTM = new JWTTabModel();
			JWTViewTab jwtVT = new JWTViewTab(jwtTM, rSyntaxTextAreaFactory);
			jwtTC = new JWTRequestTabController(jwtTM, jwtVT);
		}

		return jwtTC;
	}

	@Override
	public ExtensionProvidedHttpResponseEditor provideHttpResponseEditor(EditorCreationContext creationContext) {
		ExtensionProvidedHttpResponseEditor jwtTC;

		if (creationContext.editorMode() == EditorMode.DEFAULT) {
			JWTInterceptModel jwtSTM = new JWTInterceptModel();
			JWTInterceptTab jwtST = new JWTInterceptTab(jwtSTM, rSyntaxTextAreaFactory);
			jwtTC = new JWTResponseInterceptTabController(jwtSTM, jwtST);
		} else {
			// Read Only
			JWTTabModel jwtTM = new JWTTabModel();
			JWTViewTab jwtVT = new JWTViewTab(jwtTM, rSyntaxTextAreaFactory);
			jwtTC = new JWTResponseTabController(jwtTM, jwtVT);
		}

		return jwtTC;
	}
}

package app.controllers;

import gui.JWTInterceptTab;
import model.JWTInterceptModel;

public class JWTResponseInterceptTabController extends JWTInterceptTabController {

	public JWTResponseInterceptTabController(JWTInterceptModel jwtTM, JWTInterceptTab jwtVT) {
		super(jwtTM, jwtVT, false);
	}

}

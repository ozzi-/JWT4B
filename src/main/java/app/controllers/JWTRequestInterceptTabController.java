package app.controllers;

import gui.JWTInterceptTab;
import model.JWTInterceptModel;

public class JWTRequestInterceptTabController extends JWTInterceptTabController {

	public JWTRequestInterceptTabController(JWTInterceptModel jwtTM, JWTInterceptTab jwtVT) {
		super(jwtTM, jwtVT, true);
	}

}
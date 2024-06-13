package app.controllers;

import gui.JWTViewTab;
import model.JWTTabModel;

public class JWTResponseTabController extends JwtTabController {

	public JWTResponseTabController(JWTTabModel jwtTM, JWTViewTab jwtVT) {
		super(jwtTM, jwtVT, false);
	}

}

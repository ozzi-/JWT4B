# JWT4B
JSON Web Tokens (JWT) support for the Burp Interception Proxy. JWT4B will let you manipulate a JWT on the fly, automate common attacks against JWT and decode it for you in the proxy history. JWT4B automagically detects JWTs in the form of 'Authorization Bearer' headers as well as customizable post body parameters.

![Logo](https://i.imgur.com/SnrC5To.png)

# Screenshots
![Screenshot - Intercept View](https://i.imgur.com/Px72aUL.png)

![Screenshot - Decode View](https://i.imgur.com/DaZlBi9.png)

![Screenshot - Suite Tab View](https://i.imgur.com/71KiJJ2.png)

# Testing
The following url contains links to four pages which simulate a JWT being sent via XHR or as cookie.
 [https://oz-web.com/jwt/](https://oz-web.com/jwt/) 


## Building your own version (with Eclipse)
1. Clone repository and create new Eclipse Java Project
2. Rightclick -> Configure -> Convert to Maven Project (downloading all required libraries)
3. Open Burp -> Extender -> APIs -> Save interface files -> Copy all files to JWT4B\src\burp
4. Export runnable fat JAR including libraries
5. Load the JAR in Burp through the Extender Tab -> Extensions -> Add (Good to know: CTRL+Click on a extension to reload it)

# JWT4B
JSON Web Tokens (JWT) support for the Burp Interception Proxy. JWT4B will let you manipulate a JWT on the fly, automate common attacks against JWT and decode it for you in the proxy history.

# Screenshots
![Screenshot - Intercept View](https://i.imgur.com/EOam0rB.png)

![Screenshot - Decode View](https://i.imgur.com/DaZlBi9.png)


# Acknowledgments
The most work was done during the [Hack-Labs] (https://blog.compass-security.com/2017/01/wrap-up-hack-lab-1-2017/) offered by [Compass Security] (https://compass-security.com) to its employees.

## Building your own version (with Eclipse)
1. Clone codebase and create new Eclipse Java Project
2. Rightclick -> Configure -> Convert to Maven Project
3. Open Burp -> Extender -> APIs -> Save interface files -> Copy all files to JWT4B\src\burp
4. Export runnable fat JAR
5. Load the JAR in Burp through the Extender Tab -> Extensions -> Add (Good to know: CTRL+Click on a extension to reload it)

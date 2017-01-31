# JWT4B
JSON Web Tokens support for the Burp Interception Proxy

# Dev Env / Building your own version
1. Clone codebase and create new Eclipse Java Project
2. Rightclick -> Configure -> Convert to Maven Project
3. Open Burp -> Extender -> APIs -> Save interface files -> JWT4B\src\burp
4. Export runnable fat JAR, load JAR in Burp -> Extender -> Extensions -> Add (CTRL+Click on a extension to reload it)

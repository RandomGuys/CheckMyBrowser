CheckMyBrowser
==============

Compiler OpenSSL avec les bonnes options :
$ ./config enable-tlsext shared zlib-dynamic
$ make depend

Pour compiler CheckMyBroser, il faut référencer le répertoire d'installation d'OpenSSL dans le Makefile :
CFLAGS=... -L/chemin/vers/la/lib/compilée/à/la/main/

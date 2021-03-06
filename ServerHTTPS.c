#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <signal.h>

#include <string.h>

#include <magic.h>

#include <pthread.h>

#include <openssl/ssl.h>
#include <openssl/ssl3.h>

#include "SocketTCP.h"

#define BUF_SIZE 10000

#define NOT_FOUND "HTTP/1.1 404\r\nStatus: 404 \r\nServer: RandomServer\r\nConnection: close\r\nContent-type: text/html; charset=utf-8\r\nContent-Length: 10\r\n\r\nNot found"
#define CERT_FILE "server_certif_prod.pem"
#define KEY_FILE "server_key_prod.pem"
#define CAFILE "cert_tls_server.pem"
#define CADIR NULL

#define n2s(c,s)	((s=(((unsigned int)(c[0]))<< 8)| \
			    (((unsigned int)(c[1]))    )),c+=2)

#define MENU_HTML "<div class=\"navbar navbar-inverse navbar-fixed-top\">\
  <div class=\"navbar-inner\">\
        <div class=\"container\">\
          <a class=\"brand\" href=\"http://localhost/site/index.php\">RandomGuys</a>\
          <div class=\"nav-collapse collapse\">\
                <ul class=\"nav\">\
                  <li><a href=\"http://localhost/site/keys_stat.php\">Analyse des certificats</a></li>\
                  <li><a href=\"http://localhost/site/audit_results.php\">Audit d'OpenSSL</a></li>\
                  <li class=\"active\"><a href=\"https://localhost/site/analyze\">Test du navigateur</a></li>\
                </ul>\
          </div>\
        </div>\
  </div>\
</div>"

//#define FEW_BIT_REASON "Utilisation de clefs de chiffrement de taille inférieure à 128 bits"
//#define NULL_REASON "Pas d'algorithme de chiffrement"
//#define NULL_AUTH_REASON "Pas d'algorithme d'authentification, permet une attaque Man in the middle"

#define DANGER_FEW_BIT 1
#define DANGER_NULL 2
#define DANGER_NULL_AUTH 3
#define DANGER_MD5 4
#define DANGER_SHA1 5
SocketTCP *ecoute;

void sigaction(int s) {
	switch (s) {
	case SIGINT:
		closeSocketTCP(ecoute);
		exit(EXIT_SUCCESS);
	default:
		break;
	}
}

/**
 * Début d'idée pour les algos de signature :
 * dans le client hello, il y a un champs d'extension contenant des codes d'algos :
 * ABCD
 * AB : 04 = SHA512, 05 = SHA384, 02 = SHA1
 * CD : 01 = RSA, 02 = DSA, 03 = ECDSA
 */

int get_danger_of_cipher_suite(unsigned long cipher_id) {
	switch (cipher_id) {
	case SSL3_CK_EDH_RSA_DES_40_CBC_SHA:
	case SSL3_CK_EDH_RSA_DES_64_CBC_SHA:
	case SSL3_CK_DH_DSS_DES_40_CBC_SHA:
	case SSL3_CK_DH_DSS_DES_64_CBC_SHA:
	case SSL3_CK_DH_RSA_DES_40_CBC_SHA:
	case SSL3_CK_DH_RSA_DES_64_CBC_SHA:
	case SSL3_CK_ADH_DES_40_CBC_SHA:
	case SSL3_CK_ADH_RC4_40_MD5:
	case SSL3_CK_ADH_DES_64_CBC_SHA:
	case SSL3_CK_RSA_DES_40_CBC_SHA:
	case SSL3_CK_RSA_RC4_40_MD5:
	case SSL3_CK_RSA_DES_64_CBC_SHA:
	case SSL3_CK_KRB5_DES_40_CBC_MD5:
	case SSL3_CK_KRB5_DES_40_CBC_SHA:
	case SSL3_CK_KRB5_RC4_40_MD5:
	case SSL3_CK_KRB5_RC4_40_SHA:
	case SSL3_CK_KRB5_DES_64_CBC_MD5:
	case SSL3_CK_KRB5_DES_64_CBC_SHA:
	case TLS1_CK_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA:
	case TLS1_CK_RSA_EXPORT1024_WITH_DES_CBC_SHA:
	case TLS1_CK_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA:
		return DANGER_FEW_BIT;
	case TLS1_CK_ECDH_RSA_WITH_NULL_SHA:
	case TLS1_CK_ECDHE_ECDSA_WITH_NULL_SHA:
	case TLS1_CK_ECDH_ECDSA_WITH_NULL_SHA:
	case 0x03000000: // TLS_NULL_WITH_NULL_NULL
	case TLS1_CK_RSA_WITH_NULL_SHA256:
		return DANGER_NULL;
	case TLS1_CK_ECDH_anon_WITH_NULL_SHA:
	case TLS1_CK_ECDH_anon_WITH_DES_192_CBC3_SHA:
	case TLS1_CK_ECDH_anon_WITH_AES_128_CBC_SHA:
	case TLS1_CK_ECDH_anon_WITH_AES_256_CBC_SHA:
	case TLS1_CK_ECDH_anon_WITH_RC4_128_SHA:
	case TLS1_CK_SRP_SHA_WITH_3DES_EDE_CBC_SHA:
	case TLS1_CK_SRP_SHA_WITH_AES_128_CBC_SHA:
	case TLS1_CK_SRP_SHA_WITH_AES_256_CBC_SHA:
		return DANGER_NULL_AUTH;
	case SSL3_CK_RSA_NULL_MD5:
case SSL3_CK_RSA_RC4_128_MD5:
case SSL3_CK_RSA_RC2_40_MD5:
case SSL3_CK_ADH_RC4_128_MD5:
case SSL3_CK_KRB5_DES_192_CBC3_MD5:
case SSL3_CK_KRB5_RC4_128_MD5:
case SSL3_CK_KRB5_IDEA_128_CBC_MD5:
case SSL3_CK_KRB5_RC2_40_CBC_MD5:
case TLS1_CK_RSA_EXPORT1024_WITH_RC4_56_MD5:
case TLS1_CK_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5:
		return DANGER_MD5;
	case SSL3_CK_RSA_NULL_SHA:
case SSL3_CK_RSA_RC4_128_SHA:
case SSL3_CK_RSA_IDEA_128_SHA:
case SSL3_CK_RSA_DES_192_CBC3_SHA:
case SSL3_CK_DH_RSA_DES_192_CBC3_SHA:
case SSL3_CK_EDH_DSS_DES_40_CBC_SHA:
case SSL3_CK_EDH_DSS_DES_64_CBC_SHA:
case SSL3_CK_EDH_DSS_DES_192_CBC3_SHA:
case SSL3_CK_EDH_RSA_DES_192_CBC3_SHA:
case SSL3_CK_ADH_DES_192_CBC_SHA:
case SSL3_CK_KRB5_DES_192_CBC3_SHA:
case SSL3_CK_KRB5_RC4_128_SHA:
case SSL3_CK_KRB5_IDEA_128_CBC_SHA:
case SSL3_CK_KRB5_RC2_40_CBC_SHA:
case TLS1_CK_PSK_WITH_RC4_128_SHA:
case TLS1_CK_PSK_WITH_3DES_EDE_CBC_SHA:
case TLS1_CK_PSK_WITH_AES_128_CBC_SHA:
case TLS1_CK_PSK_WITH_AES_256_CBC_SHA:
case TLS1_CK_RSA_EXPORT1024_WITH_RC4_56_SHA:
case TLS1_CK_DHE_DSS_WITH_RC4_128_SHA:
case TLS1_CK_RSA_WITH_AES_128_SHA:
case TLS1_CK_DH_DSS_WITH_AES_128_SHA:
case TLS1_CK_DH_RSA_WITH_AES_128_SHA:
case TLS1_CK_DHE_DSS_WITH_AES_128_SHA:
case TLS1_CK_DHE_RSA_WITH_AES_128_SHA:
case TLS1_CK_ADH_WITH_AES_128_SHA:
case TLS1_CK_RSA_WITH_AES_256_SHA:
case TLS1_CK_DH_DSS_WITH_AES_256_SHA:
case TLS1_CK_DH_RSA_WITH_AES_256_SHA:
case TLS1_CK_DHE_DSS_WITH_AES_256_SHA:
case TLS1_CK_DHE_RSA_WITH_AES_256_SHA:
case TLS1_CK_ADH_WITH_AES_256_SHA:
case TLS1_CK_RSA_WITH_CAMELLIA_128_CBC_SHA:
case TLS1_CK_DH_DSS_WITH_CAMELLIA_128_CBC_SHA:
case TLS1_CK_DH_RSA_WITH_CAMELLIA_128_CBC_SHA:
case TLS1_CK_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA:
case TLS1_CK_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA:
case TLS1_CK_ADH_WITH_CAMELLIA_128_CBC_SHA:
case TLS1_CK_RSA_WITH_CAMELLIA_256_CBC_SHA:
case TLS1_CK_DH_DSS_WITH_CAMELLIA_256_CBC_SHA:
case TLS1_CK_DH_RSA_WITH_CAMELLIA_256_CBC_SHA:
case TLS1_CK_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA:
case TLS1_CK_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA:
case TLS1_CK_ADH_WITH_CAMELLIA_256_CBC_SHA:
case TLS1_CK_RSA_WITH_SEED_SHA:
case TLS1_CK_DH_DSS_WITH_SEED_SHA:
case TLS1_CK_DH_RSA_WITH_SEED_SHA:
case TLS1_CK_DHE_DSS_WITH_SEED_SHA:
case TLS1_CK_DHE_RSA_WITH_SEED_SHA:
case TLS1_CK_ADH_WITH_SEED_SHA:
case TLS1_CK_ECDH_ECDSA_WITH_RC4_128_SHA:
case TLS1_CK_ECDH_ECDSA_WITH_DES_192_CBC3_SHA:
case TLS1_CK_ECDH_ECDSA_WITH_AES_128_CBC_SHA:
case TLS1_CK_ECDH_ECDSA_WITH_AES_256_CBC_SHA:
case TLS1_CK_ECDHE_ECDSA_WITH_RC4_128_SHA:
case TLS1_CK_ECDHE_ECDSA_WITH_DES_192_CBC3_SHA:
case TLS1_CK_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:
case TLS1_CK_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:
case TLS1_CK_ECDH_RSA_WITH_RC4_128_SHA:
case TLS1_CK_ECDH_RSA_WITH_DES_192_CBC3_SHA:
case TLS1_CK_ECDH_RSA_WITH_AES_128_CBC_SHA:
case TLS1_CK_ECDH_RSA_WITH_AES_256_CBC_SHA:
case TLS1_CK_ECDHE_RSA_WITH_NULL_SHA:
case TLS1_CK_ECDHE_RSA_WITH_RC4_128_SHA:
case TLS1_CK_ECDHE_RSA_WITH_DES_192_CBC3_SHA:
case TLS1_CK_ECDHE_RSA_WITH_AES_128_CBC_SHA:
case TLS1_CK_ECDHE_RSA_WITH_AES_256_CBC_SHA:
case TLS1_CK_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA:
case TLS1_CK_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA:
case TLS1_CK_SRP_SHA_RSA_WITH_AES_128_CBC_SHA:
case TLS1_CK_SRP_SHA_DSS_WITH_AES_128_CBC_SHA:
case TLS1_CK_SRP_SHA_RSA_WITH_AES_256_CBC_SHA:
case TLS1_CK_SRP_SHA_DSS_WITH_AES_256_CBC_SHA:
	return DANGER_SHA1;

	default:
		return -1;
	}
}

char *get_version(SSL *ssl) {
	switch (ssl->version) {
	case SSL2_VERSION:
		return "SSL 2.0 <span class=\"label label-important\">MAUVAIS</span>";
	case SSL3_VERSION:
		return "SSL 3.0 <span class=\"label label-important\">MAUVAIS</span>";
	case TLS1_VERSION:
		return "TLS 1.0 <span class=\"label label-important\">MAUVAIS</span> ";
	case TLS1_1_VERSION:
		return "TLS 1.1 <span class=\"label label-info\">OK</span>";
	case TLS1_2_VERSION:
		return "TLS 1.2 <span class=\"label label-success\">BON</span>";
	case DTLS1_VERSION:
		return "DTLS 1.0 ";
	case DTLS1_BAD_VER:
		return "DTLS 1.0 (bad) ";
	default:
		return "???";
	}
}

char *get_ecc_list(SSL *ssl) {
	char *ecc = NULL;
	ecc = (char *) malloc(1024);
	memset(ecc, 0, sizeof(ecc));
	strcpy(ecc, "<h5>Courbes elliptiques :</h5>\n");
	unsigned char *clist = ssl->session->tlsext_ellipticcurvelist;
	size_t clistlen = ssl->session->tlsext_ellipticcurvelist_length / 2;
	size_t j;
	unsigned int cid, nid;
	for (size_t j = 0; j < clistlen; j++) {
		n2s(clist, cid);
		nid = tls1_ec_curve_id2nid(cid);
		if (nid != 0) {
			switch (nid) {
			case NID_sect163k1: /* sect163k1 (1) */
				strcat(ecc, "sect163k1 <span class=\"label label-default\">?</span>");
				break;
			case NID_sect163r1: /* sect163r1 (2) */
				strcat(ecc, "sect163r1 <span class=\"label label-default\">?</span>");
				break;
			case NID_sect163r2: /* sect163r2 (3) */
				strcat(ecc, "sect163r2 <span class=\"label label-default\">?</span>");
				break;
			case NID_sect193r1: /* sect193r1 (4) */
				strcat(ecc, "sect193r1 <span class=\"label label-default\">?</span>");
				break;
			case NID_sect193r2: /* sect193r2 (5) */
				strcat(ecc, "sect193r2 <span class=\"label label-default\">?</span>");
				break;
			case NID_sect233k1: /* sect233k1 (6) */
				strcat(ecc, "sect233k1 <span class=\"label label-default\">?</span>");
				break;
			case NID_sect233r1: /* sect233r1 (7) */
				strcat(ecc, "sect233r1 <span class=\"label label-default\">?</span>");
				break;
			case NID_sect239k1: /* sect239k1 (8) */
				strcat(ecc, "sect239k1 <span class=\"label label-default\">?</span>");
				break;
			case NID_sect283k1: /* sect283k1 (9) */
				strcat(ecc, "sect283k1 <span class=\"label label-default\">?</span>");
				break;
			case NID_sect283r1: /* sect283r1 (10) */
				strcat(ecc, "sect283r1 <span class=\"label label-default\">?</span>");
				break;
			case NID_sect409k1: /* sect409k1 (11) */
				strcat(ecc, "sect409k1 <span class=\"label label-default\">?</span>");
				break;
			case NID_sect409r1: /* sect409r1 (12) */
				strcat(ecc, "sect409r1 <span class=\"label label-default\">?</span>");
				break;
			case NID_sect571k1: /* sect571k1 (13) */
				strcat(ecc, "sect571k1 <span class=\"label label-default\">?</span>");
				break;
			case NID_sect571r1: /* sect571r1 (14) */
				strcat(ecc, "sect571r1 <span class=\"label label-default\">?</span>");
				break;
			case NID_secp160k1: /* secp160k1 (15) */
				strcat(ecc, "secp160k1 <span class=\"label label-default\">?</span>");
				break;
			case NID_secp160r1: /* secp160r1 (16) */
				strcat(ecc, "secp160r1 <span class=\"label label-default\">?</span>");
				break;
			case NID_secp160r2: /* secp160r2 (17) */
				strcat(ecc, "secp160r2 <span class=\"label label-default\">?</span>");
				break;
			case NID_secp192k1: /* secp192k1 (18) */
				strcat(ecc, "secp192k1 <span class=\"label label-default\">?</span>");
				break;
			case NID_X9_62_prime192v1: /* secp192r1 (19) */
				strcat(ecc, "secp192r1 <span class=\"label label-default\">?</span>");
				break;
			case NID_secp224k1: /* secp224k1 (20) */
				strcat(ecc, "secp224k1 <span class=\"label label-default\">?</span>");
				break;
			case NID_secp224r1: /* secp224r1 (21) */
				strcat(ecc, "secp224r1 <span class=\"label label-default\">?</span>");
				break;
			case NID_secp256k1: /* secp256k1 (22) */
				strcat(ecc, "secp256k1 <span class=\"label label-default\">?</span>");
				break;
			case NID_X9_62_prime256v1: /* secp256r1 (23) */
				strcat(ecc, "secp256r1 <span class=\"label label-success\">OK</span>");
				break;
			case NID_secp384r1: /* secp384r1 (24) */
				strcat(ecc, "secp384r1 <span class=\"label label-success\">OK</span>");
				break;
			case NID_secp521r1: /* secp521r1 (25) */
				strcat(ecc, "secp521r1 <span class=\"label label-default\">?</span>");
				break;
			default:
				break;
			}
			strcat(ecc, ", ");
		}
	}
	ecc[strlen(ecc) - 2] = '\0';
	return ecc;
}

char *get_cipher_suite_string(SSL_CIPHER *c) {
	switch (c->id) {
	case SSL3_CK_RSA_NULL_MD5:
		return "SSL3_RSA_NULL_MD5";
	case SSL3_CK_RSA_NULL_SHA:
		return "SSL3_RSA_NULL_SHA";
	case SSL3_CK_RSA_RC4_40_MD5:
		return "SSL3_RSA_RC4_40_MD5";
	case SSL3_CK_RSA_RC4_128_MD5:
		return "SSL3_RSA_RC4_128_MD5";
	case SSL3_CK_RSA_RC4_128_SHA:
		return "SSL3_RSA_RC4_128_SHA";
	case SSL3_CK_RSA_RC2_40_MD5:
		return "SSL3_RSA_RC2_40_MD5";
	case SSL3_CK_RSA_IDEA_128_SHA:
		return "SSL3_RSA_IDEA_128_SHA";
	case SSL3_CK_RSA_DES_40_CBC_SHA:
		return "SSL3_RSA_DES_40_CBC_SHA";
	case SSL3_CK_RSA_DES_64_CBC_SHA:
		return "SSL3_RSA_DES_64_CBC_SHA";
	case SSL3_CK_RSA_DES_192_CBC3_SHA:
		return "SSL3_RSA_DES_192_CBC3_SHA";

	case SSL3_CK_DH_DSS_DES_40_CBC_SHA:
		return "SSL3_DH_DSS_DES_40_CBC_SHA";
	case SSL3_CK_DH_DSS_DES_64_CBC_SHA:
		return "SSL3_DH_DSS_DES_64_CBC_SHA";
	case SSL3_CK_DH_DSS_DES_192_CBC3_SHA:
		return "SSL3_DH_DSS_DES_192_CBC3_SHA";
	case SSL3_CK_DH_RSA_DES_40_CBC_SHA:
		return "SSL3_DH_RSA_DES_40_CBC_SHA";
	case SSL3_CK_DH_RSA_DES_64_CBC_SHA:
		return "SSL3_DH_RSA_DES_64_CBC_SHA";
	case SSL3_CK_DH_RSA_DES_192_CBC3_SHA:
		return "SSL3_DH_RSA_DES_192_CBC3_SHA";

	case SSL3_CK_EDH_DSS_DES_40_CBC_SHA:
		return "SSL3_EDH_DSS_DES_40_CBC_SHA";

	case SSL3_CK_EDH_DSS_DES_64_CBC_SHA:
		return "SSL3_EDH_DSS_DES_64_CBC_SHA";

	case SSL3_CK_EDH_DSS_DES_192_CBC3_SHA:

		return "SSL3_DHE_RSA_DES_40_CBC_SHA";
	case SSL3_CK_EDH_RSA_DES_40_CBC_SHA:
		return "SSL3_EDH_RSA_DES_40_CBC_SHA";

	case SSL3_CK_EDH_RSA_DES_64_CBC_SHA:
		return "SSL3_EDH_RSA_DES_64_CBC_SHA";

	case SSL3_CK_EDH_RSA_DES_192_CBC3_SHA:
		return "SSL3_EDH_RSA_DES_192_CBC3_SHA";

	case SSL3_CK_ADH_RC4_40_MD5:
		return "SSL3_ADH_RC4_40_MD5";
	case SSL3_CK_ADH_RC4_128_MD5:
		return "SSL3_ADH_RC4_128_MD5";
	case SSL3_CK_ADH_DES_40_CBC_SHA:
		return "SSL3_ADH_DES_40_CBC_SHA";
	case SSL3_CK_ADH_DES_64_CBC_SHA:
		return "SSL3_ADH_DES_64_CBC_SHA";
	case SSL3_CK_ADH_DES_192_CBC_SHA:
		return "SSL3_ADH_DES_192_CBC_SHA";

		/*    VRS Additional Kerberos5 entries
		 */
	case SSL3_CK_KRB5_DES_64_CBC_SHA:
		return "SSL3_KRB5_DES_64_CBC_SHA";
	case SSL3_CK_KRB5_DES_192_CBC3_SHA:
		return "SSL3_KRB5_DES_192_CBC3_SHA";
	case SSL3_CK_KRB5_RC4_128_SHA:
		return "SSL3_KRB5_RC4_128_SHA";
	case SSL3_CK_KRB5_IDEA_128_CBC_SHA:
		return "SSL3_KRB5_IDEA_128_CBC_SHA";
	case SSL3_CK_KRB5_DES_64_CBC_MD5:
		return "SSL3_KRB5_DES_64_CBC_MD5";
	case SSL3_CK_KRB5_DES_192_CBC3_MD5:
		return "SSL3_KRB5_DES_192_CBC3_MD5";
	case SSL3_CK_KRB5_RC4_128_MD5:
		return "SSL3_KRB5_RC4_128_MD5";
	case SSL3_CK_KRB5_IDEA_128_CBC_MD5:
		return "SSL3_KRB5_IDEA_128_CBC_MD5";

	case SSL3_CK_KRB5_DES_40_CBC_SHA:
		return "SSL3_KRB5_DES_40_CBC_SHA";
	case SSL3_CK_KRB5_RC2_40_CBC_SHA:
		return "SSL3_KRB5_RC2_40_CBC_SHA";
	case SSL3_CK_KRB5_RC4_40_SHA:
		return "SSL3_KRB5_RC4_40_SHA";
	case SSL3_CK_KRB5_DES_40_CBC_MD5:
		return "SSL3_KRB5_DES_40_CBC_MD5";
	case SSL3_CK_KRB5_RC2_40_CBC_MD5:
		return "SSL3_KRB5_RC2_40_CBC_MD5";
	case SSL3_CK_KRB5_RC4_40_MD5:
		return "SSL3_KRB5_RC4_40_MD5";

		/* PSK ciphersuites from 4279 */
	case TLS1_CK_PSK_WITH_RC4_128_SHA:
		return "TLS1_PSK_WITH_RC4_128_SHA";
	case TLS1_CK_PSK_WITH_3DES_EDE_CBC_SHA:
		return "TLS1_PSK_WITH_3DES_EDE_CBC_SHA";
	case TLS1_CK_PSK_WITH_AES_128_CBC_SHA:
		return "TLS1_PSK_WITH_AES_128_CBC_SHA";
	case TLS1_CK_PSK_WITH_AES_256_CBC_SHA:
		return "TLS1_PSK_WITH_AES_256_CBC_SHA";

		/* Additional TLS ciphersuites from expired Internet Draft
		 * draft-ietf-tls-56-bit-ciphersuites-01.txt
		 case *:
		 return "*";
		 * s3_lib.c).  We actually treat them like SSL 3.0 ciphers, which we probably
		 * shouldn't.  Note that the first two are actually not in the IDs. */
	case TLS1_CK_RSA_EXPORT1024_WITH_RC4_56_MD5:
		return "TLS1_RSA_EXPORT1024_WITH_RC4_56_MD5";
	case TLS1_CK_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5:
		return "TLS1_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5";
	case TLS1_CK_RSA_EXPORT1024_WITH_DES_CBC_SHA:
		return "TLS1_RSA_EXPORT1024_WITH_DES_CBC_SHA";
	case TLS1_CK_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA:
		return "TLS1_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA";
	case TLS1_CK_RSA_EXPORT1024_WITH_RC4_56_SHA:
		return "TLS1_RSA_EXPORT1024_WITH_RC4_56_SHA";
	case TLS1_CK_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA:
		return "TLS1_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA";
	case TLS1_CK_DHE_DSS_WITH_RC4_128_SHA:
		return "TLS1_DHE_DSS_WITH_RC4_128_SHA";

		/* AES ciphersuites from RFC3268 */

	case TLS1_CK_RSA_WITH_AES_128_SHA:
		return "TLS1_RSA_WITH_AES_128_SHA";
	case TLS1_CK_DH_DSS_WITH_AES_128_SHA:
		return "TLS1_DH_DSS_WITH_AES_128_SHA";
	case TLS1_CK_DH_RSA_WITH_AES_128_SHA:
		return "TLS1_DH_RSA_WITH_AES_128_SHA";
	case TLS1_CK_DHE_DSS_WITH_AES_128_SHA:
		return "TLS1_DHE_DSS_WITH_AES_128_SHA";
	case TLS1_CK_DHE_RSA_WITH_AES_128_SHA:
		return "TLS1_DHE_RSA_WITH_AES_128_SHA";
	case TLS1_CK_ADH_WITH_AES_128_SHA:
		return "TLS1_ADH_WITH_AES_128_SHA";

	case TLS1_CK_RSA_WITH_AES_256_SHA:
		return "TLS1_RSA_WITH_AES_256_SHA";
	case TLS1_CK_DH_DSS_WITH_AES_256_SHA:
		return "TLS1_DH_DSS_WITH_AES_256_SHA";
	case TLS1_CK_DH_RSA_WITH_AES_256_SHA:
		return "TLS1_DH_RSA_WITH_AES_256_SHA";
	case TLS1_CK_DHE_DSS_WITH_AES_256_SHA:
		return "TLS1_DHE_DSS_WITH_AES_256_SHA";
	case TLS1_CK_DHE_RSA_WITH_AES_256_SHA:
		return "TLS1_DHE_RSA_WITH_AES_256_SHA";
	case TLS1_CK_ADH_WITH_AES_256_SHA:
		return "TLS1_ADH_WITH_AES_256_SHA";

		/* TLS v1.2 ciphersuites */
	case TLS1_CK_RSA_WITH_NULL_SHA256:
		return "TLS1_RSA_WITH_NULL_SHA256";
	case TLS1_CK_RSA_WITH_AES_128_SHA256:
		return "TLS1_RSA_WITH_AES_128_SHA256";
	case TLS1_CK_RSA_WITH_AES_256_SHA256:
		return "TLS1_RSA_WITH_AES_256_SHA256";
	case TLS1_CK_DH_DSS_WITH_AES_128_SHA256:
		return "TLS1_DH_DSS_WITH_AES_128_SHA256";
	case TLS1_CK_DH_RSA_WITH_AES_128_SHA256:
		return "TLS1_DH_RSA_WITH_AES_128_SHA256";
	case TLS1_CK_DHE_DSS_WITH_AES_128_SHA256:
		return "TLS1_DHE_DSS_WITH_AES_128_SHA256";

		/* Camellia ciphersuites from RFC4132 */
	case TLS1_CK_RSA_WITH_CAMELLIA_128_CBC_SHA:
		return "TLS1_RSA_WITH_CAMELLIA_128_CBC_SHA";
	case TLS1_CK_DH_DSS_WITH_CAMELLIA_128_CBC_SHA:
		return "TLS1_DH_DSS_WITH_CAMELLIA_128_CBC_SHA";
	case TLS1_CK_DH_RSA_WITH_CAMELLIA_128_CBC_SHA:
		return "TLS1_DH_RSA_WITH_CAMELLIA_128_CBC_SHA";
	case TLS1_CK_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA:
		return "TLS1_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA";
	case TLS1_CK_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA:
		return "TLS1_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA";
	case TLS1_CK_ADH_WITH_CAMELLIA_128_CBC_SHA:
		return "TLS1_ADH_WITH_CAMELLIA_128_CBC_SHA";

		/* TLS v1.2 ciphersuites */
	case TLS1_CK_DHE_RSA_WITH_AES_128_SHA256:
		return "TLS1_DHE_RSA_WITH_AES_128_SHA256";
	case TLS1_CK_DH_DSS_WITH_AES_256_SHA256:
		return "TLS1_DH_DSS_WITH_AES_256_SHA256";
	case TLS1_CK_DH_RSA_WITH_AES_256_SHA256:
		return "TLS1_DH_RSA_WITH_AES_256_SHA256";
	case TLS1_CK_DHE_DSS_WITH_AES_256_SHA256:
		return "TLS1_DHE_DSS_WITH_AES_256_SHA256";
	case TLS1_CK_DHE_RSA_WITH_AES_256_SHA256:
		return "TLS1_DHE_RSA_WITH_AES_256_SHA256";
	case TLS1_CK_ADH_WITH_AES_128_SHA256:
		return "TLS1_ADH_WITH_AES_128_SHA256";
	case TLS1_CK_ADH_WITH_AES_256_SHA256:
		return "TLS1_ADH_WITH_AES_256_SHA256";

		/* Camellia ciphersuites from RFC4132 */
	case TLS1_CK_RSA_WITH_CAMELLIA_256_CBC_SHA:
		return "TLS1_RSA_WITH_CAMELLIA_256_CBC_SHA";
	case TLS1_CK_DH_DSS_WITH_CAMELLIA_256_CBC_SHA:
		return "TLS1_DH_DSS_WITH_CAMELLIA_256_CBC_SHA";
	case TLS1_CK_DH_RSA_WITH_CAMELLIA_256_CBC_SHA:
		return "TLS1_DH_RSA_WITH_CAMELLIA_256_CBC_SHA";
	case TLS1_CK_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA:
		return "TLS1_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA";
	case TLS1_CK_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA:
		return "TLS1_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA";
	case TLS1_CK_ADH_WITH_CAMELLIA_256_CBC_SHA:
		return "TLS1_ADH_WITH_CAMELLIA_256_CBC_SHA";

		/* SEED ciphersuites from RFC4162 */
	case TLS1_CK_RSA_WITH_SEED_SHA:
		return "TLS1_RSA_WITH_SEED_SHA";
	case TLS1_CK_DH_DSS_WITH_SEED_SHA:
		return "TLS1_DH_DSS_WITH_SEED_SHA";
	case TLS1_CK_DH_RSA_WITH_SEED_SHA:
		return "TLS1_DH_RSA_WITH_SEED_SHA";
	case TLS1_CK_DHE_DSS_WITH_SEED_SHA:
		return "TLS1_DHE_DSS_WITH_SEED_SHA";
	case TLS1_CK_DHE_RSA_WITH_SEED_SHA:
		return "TLS1_DHE_RSA_WITH_SEED_SHA";
	case TLS1_CK_ADH_WITH_SEED_SHA:
		return "TLS1_ADH_WITH_SEED_SHA";

		/* TLS v1.2 GCM ciphersuites from RFC5288 */
	case TLS1_CK_RSA_WITH_AES_128_GCM_SHA256:
		return "TLS1_RSA_WITH_AES_128_GCM_SHA256";
	case TLS1_CK_RSA_WITH_AES_256_GCM_SHA384:
		return "TLS1_RSA_WITH_AES_256_GCM_SHA384";
	case TLS1_CK_DHE_RSA_WITH_AES_128_GCM_SHA256:
		return "TLS1_DHE_RSA_WITH_AES_128_GCM_SHA256";
	case TLS1_CK_DHE_RSA_WITH_AES_256_GCM_SHA384:
		return "TLS1_DHE_RSA_WITH_AES_256_GCM_SHA384";
	case TLS1_CK_DH_RSA_WITH_AES_128_GCM_SHA256:
		return "TLS1_DH_RSA_WITH_AES_128_GCM_SHA256";
	case TLS1_CK_DH_RSA_WITH_AES_256_GCM_SHA384:
		return "TLS1_DH_RSA_WITH_AES_256_GCM_SHA384";
	case TLS1_CK_DHE_DSS_WITH_AES_128_GCM_SHA256:
		return "TLS1_DHE_DSS_WITH_AES_128_GCM_SHA256";
	case TLS1_CK_DHE_DSS_WITH_AES_256_GCM_SHA384:
		return "TLS1_DHE_DSS_WITH_AES_256_GCM_SHA384";
	case TLS1_CK_DH_DSS_WITH_AES_128_GCM_SHA256:
		return "TLS1_DH_DSS_WITH_AES_128_GCM_SHA256";
	case TLS1_CK_DH_DSS_WITH_AES_256_GCM_SHA384:
		return "TLS1_DH_DSS_WITH_AES_256_GCM_SHA384";
	case TLS1_CK_ADH_WITH_AES_128_GCM_SHA256:
		return "TLS1_ADH_WITH_AES_128_GCM_SHA256";
	case TLS1_CK_ADH_WITH_AES_256_GCM_SHA384:
		return "TLS1_ADH_WITH_AES_256_GCM_SHA384";

		/* ECC ciphersuites from draft-ietf-tls-ecc-12.txt with changes soon to be in draft 13 */
	case TLS1_CK_ECDH_ECDSA_WITH_NULL_SHA:
		return "TLS1_ECDH_ECDSA_WITH_NULL_SHA";
	case TLS1_CK_ECDH_ECDSA_WITH_RC4_128_SHA:
		return "TLS1_ECDH_ECDSA_WITH_RC4_128_SHA";
	case TLS1_CK_ECDH_ECDSA_WITH_DES_192_CBC3_SHA:
		return "TLS1_ECDH_ECDSA_WITH_DES_192_CBC3_SHA";
	case TLS1_CK_ECDH_ECDSA_WITH_AES_128_CBC_SHA:
		return "TLS1_ECDH_ECDSA_WITH_AES_128_CBC_SHA";
	case TLS1_CK_ECDH_ECDSA_WITH_AES_256_CBC_SHA:
		return "TLS1_ECDH_ECDSA_WITH_AES_256_CBC_SHA";

	case TLS1_CK_ECDHE_ECDSA_WITH_NULL_SHA:
		return "TLS1_ECDHE_ECDSA_WITH_NULL_SHA";
	case TLS1_CK_ECDHE_ECDSA_WITH_RC4_128_SHA:
		return "TLS1_ECDHE_ECDSA_WITH_RC4_128_SHA";
	case TLS1_CK_ECDHE_ECDSA_WITH_DES_192_CBC3_SHA:
		return "TLS1_ECDHE_ECDSA_WITH_DES_192_CBC3_SHA";
	case TLS1_CK_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:
		return "TLS1_ECDHE_ECDSA_WITH_AES_128_CBC_SHA";
	case TLS1_CK_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:
		return "TLS1_ECDHE_ECDSA_WITH_AES_256_CBC_SHA";

	case TLS1_CK_ECDH_RSA_WITH_NULL_SHA:
		return "TLS1_ECDH_RSA_WITH_NULL_SHA";
	case TLS1_CK_ECDH_RSA_WITH_RC4_128_SHA:
		return "TLS1_ECDH_RSA_WITH_RC4_128_SHA";
	case TLS1_CK_ECDH_RSA_WITH_DES_192_CBC3_SHA:
		return "TLS1_ECDH_RSA_WITH_DES_192_CBC3_SHA";
	case TLS1_CK_ECDH_RSA_WITH_AES_128_CBC_SHA:
		return "TLS1_ECDH_RSA_WITH_AES_128_CBC_SHA";
	case TLS1_CK_ECDH_RSA_WITH_AES_256_CBC_SHA:
		return "TLS1_ECDH_RSA_WITH_AES_256_CBC_SHA";

	case TLS1_CK_ECDHE_RSA_WITH_NULL_SHA:
		return "TLS1_ECDHE_RSA_WITH_NULL_SHA";
	case TLS1_CK_ECDHE_RSA_WITH_RC4_128_SHA:
		return "TLS1_ECDHE_RSA_WITH_RC4_128_SHA";
	case TLS1_CK_ECDHE_RSA_WITH_DES_192_CBC3_SHA:
		return "TLS1_ECDHE_RSA_WITH_DES_192_CBC3_SHA";
	case TLS1_CK_ECDHE_RSA_WITH_AES_128_CBC_SHA:
		return "TLS1_ECDHE_RSA_WITH_AES_128_CBC_SHA";
	case TLS1_CK_ECDHE_RSA_WITH_AES_256_CBC_SHA:
		return "TLS1_ECDHE_RSA_WITH_AES_256_CBC_SHA";

	case TLS1_CK_ECDH_anon_WITH_NULL_SHA:
		return "TLS1_ECDH_anon_WITH_NULL_SHA";
	case TLS1_CK_ECDH_anon_WITH_RC4_128_SHA:
		return "TLS1_ECDH_anon_WITH_RC4_128_SHA";
	case TLS1_CK_ECDH_anon_WITH_DES_192_CBC3_SHA:
		return "TLS1_ECDH_anon_WITH_DES_192_CBC3_SHA";
	case TLS1_CK_ECDH_anon_WITH_AES_128_CBC_SHA:
		return "TLS1_ECDH_anon_WITH_AES_128_CBC_SHA";
	case TLS1_CK_ECDH_anon_WITH_AES_256_CBC_SHA:
		return "TLS1_ECDH_anon_WITH_AES_256_CBC_SHA";

		/* SRP ciphersuites from RFC 5054 */
	case TLS1_CK_SRP_SHA_WITH_3DES_EDE_CBC_SHA:
		return "TLS1_SRP_SHA_WITH_3DES_EDE_CBC_SHA";
	case TLS1_CK_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA:
		return "TLS1_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA";
	case TLS1_CK_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA:
		return "TLS1_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA";
	case TLS1_CK_SRP_SHA_WITH_AES_128_CBC_SHA:
		return "TLS1_SRP_SHA_WITH_AES_128_CBC_SHA";
	case TLS1_CK_SRP_SHA_RSA_WITH_AES_128_CBC_SHA:
		return "TLS1_SRP_SHA_RSA_WITH_AES_128_CBC_SHA";
	case TLS1_CK_SRP_SHA_DSS_WITH_AES_128_CBC_SHA:
		return "TLS1_SRP_SHA_DSS_WITH_AES_128_CBC_SHA";
	case TLS1_CK_SRP_SHA_WITH_AES_256_CBC_SHA:
		return "TLS1_SRP_SHA_WITH_AES_256_CBC_SHA";
	case TLS1_CK_SRP_SHA_RSA_WITH_AES_256_CBC_SHA:
		return "TLS1_SRP_SHA_RSA_WITH_AES_256_CBC_SHA";
	case TLS1_CK_SRP_SHA_DSS_WITH_AES_256_CBC_SHA:
		return "TLS1_SRP_SHA_DSS_WITH_AES_256_CBC_SHA";

		/* ECDH HMAC based ciphersuites from RFC5289 */

	case TLS1_CK_ECDHE_ECDSA_WITH_AES_128_SHA256:
		return "TLS1_ECDHE_ECDSA_WITH_AES_128_SHA256";
	case TLS1_CK_ECDHE_ECDSA_WITH_AES_256_SHA384:
		return "TLS1_ECDHE_ECDSA_WITH_AES_256_SHA384";
	case TLS1_CK_ECDH_ECDSA_WITH_AES_128_SHA256:
		return "TLS1_ECDH_ECDSA_WITH_AES_128_SHA256";
	case TLS1_CK_ECDH_ECDSA_WITH_AES_256_SHA384:
		return "TLS1_ECDH_ECDSA_WITH_AES_256_SHA384";
	case TLS1_CK_ECDHE_RSA_WITH_AES_128_SHA256:
		return "TLS1_ECDHE_RSA_WITH_AES_128_SHA256";
	case TLS1_CK_ECDHE_RSA_WITH_AES_256_SHA384:
		return "TLS1_ECDHE_RSA_WITH_AES_256_SHA384";
	case TLS1_CK_ECDH_RSA_WITH_AES_128_SHA256:
		return "TLS1_ECDH_RSA_WITH_AES_128_SHA256";
	case TLS1_CK_ECDH_RSA_WITH_AES_256_SHA384:
		return "TLS1_ECDH_RSA_WITH_AES_256_SHA384";

		/* ECDH GCM based ciphersuites from RFC5289 */
	case TLS1_CK_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
		return "TLS1_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256";
	case TLS1_CK_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
		return "TLS1_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384";
	case TLS1_CK_ECDH_ECDSA_WITH_AES_128_GCM_SHA256:
		return "TLS1_ECDH_ECDSA_WITH_AES_128_GCM_SHA256";
	case TLS1_CK_ECDH_ECDSA_WITH_AES_256_GCM_SHA384:
		return "TLS1_ECDH_ECDSA_WITH_AES_256_GCM_SHA384";
	case TLS1_CK_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
		return "TLS1_ECDHE_RSA_WITH_AES_128_GCM_SHA256";
	case TLS1_CK_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
		return "TLS1_ECDHE_RSA_WITH_AES_256_GCM_SHA384";
	case TLS1_CK_ECDH_RSA_WITH_AES_128_GCM_SHA256:
		return "TLS1_ECDH_RSA_WITH_AES_128_GCM_SHA256";
	case TLS1_CK_ECDH_RSA_WITH_AES_256_GCM_SHA384:
		return "TLS1_ECDH_RSA_WITH_AES_256_GCM_SHA384";
	default:
		return c->name;
	}
}

char *get_cipher_suite_list(SSL *ssl) {
	char *cipher_suite;
	cipher_suite = (char *) malloc(8192);
	memset(cipher_suite, 0, sizeof(cipher_suite));
	STACK_OF(SSL_CIPHER) *clnt = ssl->session->ciphers;
	SSL_CIPHER *c;
	SSL_CIPHER *current_cipher = ssl->session->cipher;
	int i;
	strcpy(cipher_suite,
			"<h5>Algorithmes de chiffrement supportés :</h5>\n<table id=\"ciphersuites\" class=\"table table-striped table-condensed\">");
	for (i = 0; i < sk_SSL_CIPHER_num(clnt); ++i) {
		c = sk_SSL_CIPHER_value(clnt, i);
		char tmp[500] = "";
		int danger = -1;
		danger = get_danger_of_cipher_suite(c->id);
		if (danger > 0) {
			printf("There is a danger: %d\n", danger);
			switch (danger) {
			case DANGER_FEW_BIT:
				sprintf(tmp,"<tr><td><a class=\"danger\" href=\"#\" data-toggle=\"tooltip\" title=\"\" data-original-title=\"Utilisation de clefs de chiffrement de taille inférieure à 128 bits\"><span class=\"label label-danger\">&nbsp;</span> %s</a></td><td>%d bits</td></tr>",	 get_cipher_suite_string(c), c->alg_bits);
				break;
			case DANGER_NULL:
				sprintf(tmp,"<tr><td><a class=\"danger\" href=\"#\" data-toggle=\"tooltip\" title=\"\" data-original-title=\"Pas d'algorithme de chiffrement\"><span class=\"label label-danger\">&nbsp;</span> %s</a></td><td>%d bits</td></tr>",	 get_cipher_suite_string(c), c->alg_bits);
								break;
			case DANGER_NULL_AUTH:
				sprintf(tmp,"<tr><td><a class=\"danger\" href=\"#\" data-toggle=\"tooltip\" title=\"\" data-original-title=\"Pas d'algorithme d'authentification, permet une attaque Man in the middle\"><span class=\"label label-danger\">&nbsp;</span> %s</a></td><td>%d bits</td></tr>",	 get_cipher_suite_string(c), c->alg_bits);
								break;
			case DANGER_MD5:
				sprintf(tmp,"<tr class=\"error\"><td><a class=\"danger\" href=\"#\" data-toggle=\"tooltip\" title=\"\" data-original-title=\"MD5 est à proscrire de nos jours\"><span class=\"label label-important\">&nbsp;</span> %s</a></td><td>%d bits</td></tr>",	 get_cipher_suite_string(c), c->alg_bits);
				break;
			case DANGER_SHA1:
				sprintf(tmp,"<tr class=\"warning\"><td><a class=\"danger\" href=\"#\" data-toggle=\"tooltip\" title=\"\" data-original-title=\"Il existe des attaques théoriques sur SHA-1\"><span class=\"label label-warning\">&nbsp;</span> %s</a></td><td>%d bits</td></tr>",	 get_cipher_suite_string(c), c->alg_bits);
			default:
				break;
			}

		} else if (current_cipher->id == c->id) {
			sprintf(tmp,
					"<tr class=\"success\"><td><span class=\"label label-success\">&nbsp;</span> %s</td><td>%d bits</td></tr>",
					get_cipher_suite_string(c), c->alg_bits);
		} else {
			sprintf(tmp, "<tr><td><span class=\"label label-success\">&nbsp;</span> %s</td><td>%d bits</td></tr>",
					get_cipher_suite_string(c), c->alg_bits);
		}
		strcat(cipher_suite, tmp);
	}
	strcat(cipher_suite, "</table>\n");
	return cipher_suite;
}

char *get_sig_algs(SSL *ssl) {
	char *sig_algs;
	sig_algs = (char *) malloc(1024);
	memset(sig_algs, 0, 1024);
	strcpy(sig_algs,
			"<h5>Algorithmes de signatures :</h5>\n<table class=\"table table-striped table-condensed\">");
	int nsig = SSL_get_sigalgs(ssl, -1, NULL, NULL, NULL, NULL, NULL);
	for (int i = 0; i < nsig; i++) {
		int hash_nid, sign_nid;
		unsigned char rhash, rsign;
		const char *sstr = NULL;
		SSL_get_sigalgs(ssl, i, &sign_nid, &hash_nid, NULL, &rsign, &rhash);

		if (sign_nid == EVP_PKEY_RSA)
			sstr = "<tr><td>RSA/";
		else if (sign_nid == EVP_PKEY_DSA)
			sstr = "<tr><td>DSA/";
		else if (sign_nid == EVP_PKEY_EC)
			sstr = "<tr><td>ECDSA/";
		if (sstr)
			strcat(sig_algs, sstr);
		else {
			char ssstr[20] = "";
			sprintf(ssstr, "0x%02X/", (int) rsign);
			strcat(sig_algs, ssstr);
		}
		if (hash_nid != NID_undef) {
			strcat(sig_algs, OBJ_nid2sn(hash_nid));
			strcat(sig_algs, "</td></tr>");
		} else {
			char ssstr[20] = "";
			sprintf(ssstr, "0x%02X", (int) rhash);
			strcat(sig_algs, ssstr);
			strcat(sig_algs, "</td></tr>");
		}
	}
	strcat(sig_algs, "</table>\n");
	return sig_algs;
}

char *get_analyze_page(SSL *ssl) {
	int version = ssl->version;
	char *str_version = get_version(ssl);

	char sig_algs[1024] = "", reply_body[BUF_SIZE] = "";
	char *ecc = NULL;
	char *reply = NULL;
	reply = (char *) malloc(BUF_SIZE);

	memset(reply, 0, sizeof(reply));
	memset(reply_body, 0, sizeof(reply_body));

	strcpy(reply,
			"HTTP/1.1 200 OK\r\nStatus: 200 OK\r\nServer: RandomServer\r\nConnection: close\r\nContent-type: text/html; charset=utf-8\r\nContent-Length: ");

	if (ssl->session->tlsext_ellipticcurvelist_length > 0) {
		ecc = get_ecc_list(ssl);
	}

	char length[100];
	memset(length, 0, sizeof(length));

	strcpy(reply_body,
			"<!DOCTYPE html><html><head><meta http-equiv=\"content-type\" content=\"text/html; charset=utf-8\" />\n<title>Analyse navigateur client</title><meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\"><link href=\"bootstrap/css/bootstrap.min.css\" rel=\"stylesheet\" media=\"screen\"><script src=\"bootstrap/js/jquery-2.0.3.min.js\"></script><script src=\"bootstrap/js/bootstrap.min.js\"></script></head><body>");
	strcat(reply_body, MENU_HTML);
	strcat(reply_body, " <div class=\"container\"><h5>Version du protocole : ");
	strcat(reply_body, str_version);
	strcat(reply_body, "</h5>\n");
	strcat(reply_body, "<h5>Compression : ");
	if (ssl->compress) {
		strcat(reply_body, "oui <span class=\"label label-important\">MAUVAIS</span></h5>");
	} else {
		strcat(reply_body, "non <span class=\"label label-success\">BON</span></h5>");
	}
	int nsig = SSL_get_sigalgs(ssl, -1, NULL, NULL, NULL, NULL, NULL);
	if (nsig > 0) {
		strcat(reply_body, "<div class=\"row\"><div class=\"span6\">");
	}
	char *cipher_suite = get_cipher_suite_list(ssl);
	strcat(reply_body, cipher_suite);
	free (cipher_suite);

	
	strcat(reply_body, "</div><div class=\"span6\">");
	if (nsig > 0 || ecc != NULL) {
		if (nsig > 0) {
			char *sig_algs = get_sig_algs(ssl);
			strcat(reply_body, sig_algs);
			free (sig_algs);
		}
		if (ecc) {
			strcat(reply_body, ecc);
			free (ecc);
		}
		if (ssl->tlsext_ticket_expected) {
			strcat(reply_body, "<h5>Ticket de session : Oui <span class=\"label label-success\">BON</span></h5>");
		} else {
			strcat(reply_body, "<h5>Ticket de session : Non <span class=\"label label-important\">MAUVAIS</span></h5>");
		}
	}
	strcat(reply_body, "<h5>Légende :</h5>\n<table class=\"table table-striped table-condensed\"> \
	<tr class=\"success\"><td>Suite en cours d'utilisation</td></tr>\
	<tr><td><span class=\"label label-success\">&nbsp;</span> Suite acceptable</td></tr>\
	<tr class=\"warning\"><td><span class=\"label label-warning\">&nbsp;</span> Attention à cette suite</td></tr>\
	<tr class=\"error\"><td><span class=\"label label-important\">&nbsp;</span> Suite dangereuse</td></tr>\
	</table><br /> \
	<span class=\"label label-success\">BON</span></h5> <span class=\"label label-success\">OK</span></h5> : acceptable<br />\
	<span class=\"label label-important\">MAUVAIS</span></h5> : dangereux<br />\
	<span class=\"label label-default\">?</span> : probablement bon</div>");

	strcat(reply_body,
			"</div><script>$(document).ready(function() { \
             $('.danger').tooltip(); \
             }); \
			</script></body></html>");

	sprintf(length, "%d\r\n\r\n", strlen(reply_body));
	strcat(reply, length);
	strcat(reply, reply_body);
	return reply;
}

void *handle_connection(void * param) {
	printf ("---- BEGIN handle_connection\n");
	SocketTCP *client = (SocketTCP *) param;

	int bytes;
	char buf[1024] = "", first_reply[512] = "HTTP/1.1 200 OK\r\n\r\n";

	SSL_METHOD *method;
	method = SSLv23_server_method(); /* create server instance */
	SSL_CTX *ctx;
	ctx = SSL_CTX_new(method); /* create context */
//	if (SSL_CTX_load_verify_locations(ctx, CAFILE, CADIR) != 1)
//		fprintf(stderr, "Error loading CA file or directory\n");
	if (SSL_CTX_use_certificate_chain_file(ctx, CERT_FILE) != 1) {
		fprintf(stderr, "Error loading certificate from file\n");
		SSL_CTX_free (ctx);
		closeSocketTCP(client);
		pthread_exit (0);
		return NULL;;
	}
	if (SSL_CTX_use_PrivateKey_file(ctx, KEY_FILE, SSL_FILETYPE_PEM) != 1) {
		printf(stderr, "Error loading private key from file\n");
		SSL_CTX_free (ctx);
		closeSocketTCP(client);
		pthread_exit(0);
		return NULL;
	}

	SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
	SSL_CTX_set_cipher_list(ctx, "ALL");

	SSL *ssl = SSL_new(ctx); /* get new SSL state with context */
	if (ssl == NULL) {
		fprintf(stderr, "Error creating SSL\n");
		SSL_CTX_free (ctx);
                closeSocketTCP(client);
                pthread_exit(0);
                return NULL;

	}
	SSL_set_fd(ssl, client->socket); /* set connection to SSL state */
	SSL_set_mode(ctx, SSL_MODE_AUTO_RETRY);
	if (SSL_accept(ssl) <= 0) { /* do SSL-protocol accept */
		printf("SSL_accept failed\n");
		ERR_print_errors_fp(stderr);
		SSL_CTX_free (ctx);
                closeSocketTCP(client);
                pthread_exit(0);
                return NULL;
	}
	printf("new SSL connection\n");

//print_sig_algs (ssl);

	memset(buf, 0, sizeof(buf));
	while ((bytes = SSL_read(ssl, buf, sizeof(buf))) > 0
			|| bytes == SSL_ERROR_WANT_READ) { /* get HTTP request */
		if (bytes == SSL_ERROR_WANT_READ) {
			printf("SSL_ERROR_WANT_READ\n");
			continue;
		}
		printf("HTTP REQUEST : %s\n", buf);
		/*...process request */
		char *s = strtok(buf, " ");
		printf("s = %s\n", s);
		char meth[10];
		memset(meth, 0, 10);
		strcpy(meth, s);

		s = strtok(NULL, " ");
		printf("s = %s, meth = %s\n", s, meth);
		if (s != NULL && strcmp(s, "/site/analyze") == 0) {
			char *res = get_analyze_page(ssl);
			printf("Reply = <%s>\n", res);
			printf("Sending cipher suite... (%d bytes)\n", strlen(res));
			SSL_write(ssl, res, strlen(res)); /* send reply */
			free (res);
			printf("Done.\n");
			break;
		} else if (s != NULL) {
			if (strcmp(meth, "GET") == 0) {
				printf("Nom du fichier : %s\n", s);
				char filename[64];
				strcpy(filename, s + 1);

				int fd;
				if ((fd = open(filename, O_RDONLY)) == -1) {
					perror("open");
					SSL_write(ssl, NOT_FOUND, strlen(NOT_FOUND));
					continue;
				}
				size_t sz = lseek(fd, 0L, SEEK_END);
				lseek(fd, 0L, SEEK_SET);
				magic_t magic = magic_open(MAGIC_MIME);
				magic_load(magic, NULL);
				char *mime_type = magic_file(magic, filename);
				printf("Mime_type = <%s>\n", mime_type);

				char message[BUFSIZ];
				memset(message, 0, sizeof(message));
				strcpy(message, "HTTP/1.1 200 OK\nContent-type: ");
				if (strcmp(filename + strlen(filename) - 4, ".css") == 0) {
					strcat(message, "text/css");
				} else if (strcmp(filename + strlen(filename) - 3, ".js")
						== 0) {
					strcat(message, "application/javascript");
				} else {
					strcat(message, mime_type);
				}
				magic_close(magic);
				strcat(message, "\nContent-length: ");
				char lengthstr[100];
				sprintf(lengthstr, "%d", sz);
				strcat(message, lengthstr);
				strcat(message, "\n\n");
				SSL_write(ssl, message, strlen(message));
				int read_size;
				char buffer[4096];
				while ((read_size = read(fd, buffer, BUF_SIZE)) > 0) {
					SSL_write(ssl, buffer, read_size);
				}

			}
		}
		memset(buf, 0, sizeof(buf));

	}
	printf ("bytes = %d\n", bytes);
	if (bytes <= 0) {
		ERR_print_errors_fp(stderr);
	}

	/*...*/
	/* close connection & clean up */
	SSL_shutdown(ssl);
	closeSocketTCP(client);
	SSL_free(ssl); /* release SSL state */
	SSL_CTX_free (ctx);
	pthread_exit(0);

	return NULL;
}

void new_thread(SocketTCP *socket) {
	int ret;

	pthread_attr_t attr;
	if ((ret = pthread_attr_init(&attr)) != 0) {
		fprintf(stderr, "pthread_attr_init: %s\n", strerror(ret));
		exit(EXIT_FAILURE);
	}

// On dÃ©tache le thread afin de ne pas avoir Ã  faire de join
	if ((ret = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED))
			!= 0) {
		fprintf(stderr, "pthread_attr_setdetachstate: %s\n", strerror(ret));
		exit(EXIT_FAILURE);
	}

	pthread_t t;
	if ((ret = pthread_create(&t, NULL, handle_connection, (void*) socket))
			!= 0) {
		fprintf(stderr, "pthead_create: %s\n", strerror(ret));
		exit(EXIT_FAILURE);
	}

	if ((ret = pthread_attr_destroy(&attr)) != 0) {
		fprintf(stderr, "pthread_attr_destroy: %s\n", strerror(ret));
		exit(EXIT_FAILURE);
	}

}

int main(int argc, char *argv[]) {
	SocketTCP *client;

	OpenSSL_add_all_algorithms(); /* load & register cryptos */
	SSL_library_init();
	SSL_load_error_strings(); /* load all error messages */
	ERR_load_BIO_strings();

	if ((ecoute = creerSocketEcouteTCP(argv[1], atoi(argv[2]))) == NULL) {
		perror("creerSocketEcouteTCP");
		exit(EXIT_FAILURE);
	}
	(void) signal(SIGINT, sigaction);
	while (1) {
		printf("Waiting for connection...\n");
		client = acceptSocketTCP(ecoute);
		printf("New connection client = %d!\n", client->socket);
		new_thread(client);
	}
	exit(EXIT_SUCCESS);
}

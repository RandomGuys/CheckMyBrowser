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

#include "SocketTCP.h"

#define BUF_SIZE 10000

#define NOT_FOUND "HTTP/1.1 404 Not Found\n\n"
#define CERT_FILE "cert_tls_server.pem"
#define KEY_FILE "key_tls_server.pem"
#define CAFILE "cert_tls_server.pem"
#define CADIR NULL

#define n2s(c,s)	((s=(((unsigned int)(c[0]))<< 8)| \
			    (((unsigned int)(c[1]))    )),c+=2)

#define MENU_HTML "<div class=\"navbar navbar-inverse navbar-fixed-top\">\
  <div class=\"navbar-inner\">\
        <div class=\"container\">\
          <a class=\"brand\" href=\"index.php\">RandomGuys</a>\
          <div class=\"nav-collapse collapse\">\
                <ul class=\"nav\">\
                  <li><a href=\"keys_stat.php\">Analyse des certificats</a></li>\
                  <li><a href=\"audit_results.php\">Audit d'OpenSSL</a></li>\
                  <li class=\"active\"><a href=\"scan_client.php\">Test du navigateur</a></li>\
                </ul>\
          </div>\
        </div>\
  </div>\
</div>"

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

char *get_analyze_page(SSL *ssl) {
	int version = ssl->version;
	char str_version[10];
	memset(str_version, 0, sizeof(str_version));
	switch (version) {
	case SSL2_VERSION:
		strcpy(str_version, "SSL 2.0");
		break;
	case SSL3_VERSION:
		strcpy(str_version, "SSL 3.0 ");
		break;
	case TLS1_VERSION:
		strcpy(str_version, "TLS 1.0 ");
		break;
	case TLS1_1_VERSION:
		strcpy(str_version, "TLS 1.1 ");
		break;
	case TLS1_2_VERSION:
		strcpy(str_version, "TLS 1.2 ");
		break;
	case DTLS1_VERSION:
		strcpy(str_version, "DTLS 1.0 ");
		break;
	case DTLS1_BAD_VER:
		strcpy(str_version, "DTLS 1.0 (bad) ");
		break;
	default:
		strcpy(str_version, "???");
	}

	char reply[BUF_SIZE] = "", cipher_suite[4096] = "", sig_algs[1024] = "",
			reply_body[BUF_SIZE] = "", ecc[1024] = "";
	memset(reply, 0, sizeof(reply));
	memset(reply_body, 0, sizeof(reply_body));
	memset(cipher_suite, 0, sizeof(cipher_suite));
	memset(ecc, 0, sizeof(ecc));

	strcpy(reply,
			"HTTP/1.1 200 OK\r\nStatus: 200 OK\r\nServer: RandomServer\r\nConnection: close\r\nContent-type: text/html; charset=utf-8\r\nContent-Length: ");

	int nsig = SSL_get_sigalgs(ssl, -1, NULL, NULL, NULL, NULL, NULL);
	if (nsig > 0) {
		strcpy(sig_algs,
				"<h5>Algorithmes de signatures :</h5>\n<table class=\"table table-striped\">");
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
	}
	printf ("ssl->tlsext_ellipticcurvelist_length = %u", ssl->session->tlsext_ellipticcurvelist_length);
	if (ssl->session->tlsext_ellipticcurvelist_length > 0) {
		strcpy(ecc,
				"<h5>Courbes elliptiques :</h5>\n");
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
					strcat(ecc, "sect163k1");
					break;
				case NID_sect163r1: /* sect163r1 (2) */
					strcat(ecc, "sect163r1");
					break;
				case NID_sect163r2: /* sect163r2 (3) */
					strcat(ecc, "sect163r2");
					break;
				case NID_sect193r1: /* sect193r1 (4) */
					strcat(ecc, "sect193r1");
					break;
				case NID_sect193r2: /* sect193r2 (5) */
					strcat(ecc, "sect193r2");
					break;
				case NID_sect233k1: /* sect233k1 (6) */
					strcat(ecc, "sect233k1");
					break;
				case NID_sect233r1: /* sect233r1 (7) */
					strcat(ecc, "sect233r1");
					break;
				case NID_sect239k1: /* sect239k1 (8) */
					strcat(ecc, "sect239k1");
					break;
				case NID_sect283k1: /* sect283k1 (9) */
					strcat(ecc, "sect283k1");
					break;
				case NID_sect283r1: /* sect283r1 (10) */
					strcat(ecc, "sect283r1");
					break;
				case NID_sect409k1: /* sect409k1 (11) */
					strcat(ecc, "sect409k1");
					break;
				case NID_sect409r1: /* sect409r1 (12) */
					strcat(ecc, "sect409r1");
					break;
				case NID_sect571k1: /* sect571k1 (13) */
					strcat(ecc, "sect571k1");
					break;
				case NID_sect571r1: /* sect571r1 (14) */
					strcat(ecc, "sect571r1");
					break;
				case NID_secp160k1: /* secp160k1 (15) */
					strcat(ecc, "secp160k1");
					break;
				case NID_secp160r1: /* secp160r1 (16) */
					strcat(ecc, "secp160r1");
					break;
				case NID_secp160r2: /* secp160r2 (17) */
					strcat(ecc, "secp160r2");
					break;
				case NID_secp192k1: /* secp192k1 (18) */
					strcat(ecc, "secp192k1");
					break;
				case NID_X9_62_prime192v1: /* secp192r1 (19) */
					strcat(ecc, "secp192r1");
					break;
				case NID_secp224k1: /* secp224k1 (20) */
					strcat(ecc, "secp224k1");
					break;
				case NID_secp224r1: /* secp224r1 (21) */
					strcat(ecc, "secp224r1");
					break;
				case NID_secp256k1: /* secp256k1 (22) */
					strcat(ecc, "secp256k1");
					break;
				case NID_X9_62_prime256v1: /* secp256r1 (23) */
					strcat(ecc, "secp256r1");
					break;
				case NID_secp384r1: /* secp384r1 (24) */
					strcat(ecc, "secp384r1");
					break;
				case NID_secp521r1: /* secp521r1 (25) */
					strcat(ecc, "secp521r1");
					break;
				default:
					break;
				}
				strcat(ecc, ", ");
			}
		}
		ecc[strlen(ecc) - 2] = '\0';
	}

	STACK_OF(SSL_CIPHER) *clnt = ssl->session->ciphers;
	SSL_CIPHER *c;
	SSL_CIPHER *current_cipher = ssl->session->cipher;
	int i;
	strcpy(cipher_suite,
			"<h5>Algorithmes de chiffrement supportés :</h5>\n<table class=\"table table-striped\">");
	for (i = 0; i < sk_SSL_CIPHER_num(clnt); ++i) {
		c = sk_SSL_CIPHER_value(clnt, i);
		char tmp[100] = "";
		if (current_cipher->id == c->id) {
			sprintf(tmp,
					"<tr class=\"success\"><td>%s</td><td>%d bits</td></tr>",
					c->name, c->alg_bits);
		} else {
			sprintf(tmp, "<tr><td>%s</td><td>%d bits</td></tr>", c->name,
					c->alg_bits);
		}
		strcat(cipher_suite, tmp);
	}
	strcat(cipher_suite, "</table>\n");
	char length[100];
	memset(length, 0, sizeof(length));
//sprintf(length, "%d\r\n\r\n", strlen(cipher_suite) + strlen (sig_algs) + 1);

	strcpy(reply_body,
			"<!DOCTYPE html><html><head><meta http-equiv=\"content-type\" content=\"text/html; charset=utf-8\" />\n<title>Analyse navigateur client</title><meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\"><link href=\"bootstrap/css/bootstrap.min.css\" rel=\"stylesheet\" media=\"screen\"></head><body>");
	strcat(reply_body, MENU_HTML);
	strcat(reply_body, " <div class=\"container\"><h5>Version du protocole : ");
	strcat(reply_body, str_version);
	strcat(reply_body, "</h5>\n");
	strcat(reply_body, "<h5>Compression : ");
	if (ssl->compress) {
		strcat(reply_body, "oui</h5>");
	} else {
		strcat(reply_body, "non</h5>");
	}
	if (nsig > 0) {
		strcat(reply_body, "<div class=\"row\"><div class=\"span6\">");
	}
	strcat(reply_body, cipher_suite);
	if (nsig > 0 || strlen(ecc) > 0) {
		strcat(reply_body, "</div><div class=\"span6\">");
		if (nsig > 0) {
			strcat(reply_body, sig_algs);
		}
		if (strlen(ecc) > 0) {
			strcat(reply_body, ecc);
		}
		strcat(reply_body, "</div>");
	}

	strcat(reply_body, "</div></body></html>");

	sprintf(length, "%d\r\n\r\n", strlen(reply_body));
	strcat(reply, length);
	strcat(reply, reply_body);
}

void *handle_connection(void * param) {
	SocketTCP *client = (SocketTCP *) param;

	int bytes;
	char buf[1024] = "", first_reply[512] = "HTTP/1.1 200 OK\r\n\r\n";

	SSL_METHOD *method;
	method = SSLv23_server_method(); /* create server instance */
	SSL_CTX *ctx;
	ctx = SSL_CTX_new(method); /* create context */
//	if (SSL_CTX_load_verify_locations(ctx, CAFILE, CADIR) != 1)
//		fprintf(stderr, "Error loading CA file or directory\n");
	if (SSL_CTX_use_certificate_chain_file(ctx, CERT_FILE) != 1)
		fprintf(stderr, "Error loading certificate from file\n");
	if (SSL_CTX_use_PrivateKey_file(ctx, KEY_FILE, SSL_FILETYPE_PEM) != 1)
		fprintf(stderr, "Error loading private key from file\n");

	SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
	SSL_CTX_set_cipher_list(ctx, "ALL");

	SSL *ssl = SSL_new(ctx); /* get new SSL state with context */
	if (ssl == NULL) {
		fprintf(stderr, "Error creating SSL\n");
	}
	SSL_set_fd(ssl, client->socket); /* set connection to SSL state */
	SSL_set_mode(ctx, SSL_MODE_AUTO_RETRY);
	if (SSL_accept(ssl) <= 0) { /* do SSL-protocol accept */
		printf("SSL_accept failed\n");
		ERR_print_errors_fp(stderr);
	}
	printf("new SSL connection\n");

//print_sig_algs (ssl);

	memset(buf, 0, sizeof(buf));
	while ((bytes = SSL_read(ssl, buf, sizeof(buf))) > 0
			|| bytes == SSL_ERROR_WANT_READ) { /* get HTTP request */
		printf("HTTP REQUEST : %s\n", buf);
		/*...process request */
		char *s = strtok(buf, " ");
		if (strcmp(s, "GET") == 0) {
			s = strtok(NULL, " ");
			printf("s = %s\n", s);
			if (s != NULL && strcmp(s, "/analyze") == 0) {
				char *res = get_analyze_page(ssl);
				printf("Reply = <%s>\n", res);
				printf("Sending cipher suite... (%d bytes)\n", strlen(res));
				SSL_write(ssl, res, strlen(res)); /* send reply */

				printf("Done.\n");
				break;
			} else {
				printf("Nom du fichier : %s\n", s);
				char filename[64];
				strcpy(filename, s + 1);

				int fd;
				if ((fd = open(filename, O_RDONLY)) == -1) {
					perror("open");
					SSL_write(ssl, NOT_FOUND, strlen(NOT_FOUND));
					break;
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
				break;
			}
		}
		memset(buf, 0, sizeof(buf));

	}
	if (bytes <= 0) {
		ERR_print_errors_fp(stderr);
	}

	/*...*/
	/* close connection & clean up */
	SSL_shutdown(ssl);
	closeSocketTCP(client);
	SSL_free(ssl); /* release SSL state */

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
		printf("New connection !\n");
		new_thread(client);
	}
	exit(EXIT_SUCCESS);
}

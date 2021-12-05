#include <stdio.h>
#include <strings.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

void print_usage(void)
{
    fprintf(stderr, "usage: getcert <username> <password>\n");
}

/*
 * Building on prof Bellovin's sample SSL client
 */

int main(int argc, char **argv)
{
    SSL_CTX *ctx;
    SSL *ssl;
    BIO *sbio;
    int err; char *s;

    int n;
    int ilen;
    char ibuf[512];
    char obuf[512];

    struct sockaddr_in sin;
    int sock;
    struct hostent *he;




    // TODO: these should be command line arguments.......
    int s_port = 79996; //79998; //443; //79999;
    char hostname[1024];

    /* Load encryption & hash algorithms for SSL */
    SSL_library_init();
    SSL_load_error_strings();
    ctx = SSL_CTX_new(TLS_client_method());
    SSL_CTX_set_default_verify_dir(ctx);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | 
            SSL_OP_NO_COMPRESSION);
    SSL_CTX_set_cipher_list(ctx, "HIGH:!aNULL:!kRSA:!PSK:!SRP:!MD5:!RC4");
    ssl = SSL_new(ctx);
    SSL_set_tlsext_host_name(ssl, "localhost");  

    /* Load all certificates, CA Authority, private keys */
    /*    if (SSL_use_certificate_file(ssl, cert_file, cert_type) <= 0) {
          ERR_print_errors_fp(stderr);
          exit(1);
          }

          if (SSL_use_PrivateKey_file(ssl, priv_key_file, key_type) <= 0) {
          ERR_print_errors_fp(stderr);
          exit(1);
          }

          if (!SSL_CTX_load_verify_locations(ctx, NULL, CApath)) {
          ERR_print_errors_fp(stderr);
          exit(1);
          }
          */
    /* Set up a Connecting Client Socket */
    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0) {
        perror("socket");
        return 1;
    }

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons(s_port);
    he = gethostbyname("localhost");


    memcpy(&sin.sin_addr, (struct in_addr *)he->h_addr, he->h_length);
    if (connect(sock, (struct sockaddr *)&sin, sizeof sin) < 0) {
        perror("connect");
        return 2;
    }

    sbio = BIO_new(BIO_s_socket());
    BIO_set_fd(sbio, sock, BIO_NOCLOSE);
    SSL_set_bio(ssl, sbio, sbio);
    err = SSL_connect(ssl);

    if (SSL_connect(ssl) != 1) {
        switch (SSL_get_error(ssl, err)) {
            case SSL_ERROR_NONE: s="SSL_ERROR_NONE"; break;
            case SSL_ERROR_ZERO_RETURN: s="SSL_ERROR_ZERO_RETURN"; break;
            case SSL_ERROR_WANT_READ: s="SSL_ERROR_WANT_READ"; break;
            case SSL_ERROR_WANT_WRITE: s="SSL_ERROR_WANT_WRITE"; break;
            case SSL_ERROR_WANT_CONNECT: s="SSL_ERROR_WANT_CONNECT"; break;
            case SSL_ERROR_WANT_ACCEPT: s="SSL_ERROR_WANT_ACCEPT"; break;
            case SSL_ERROR_WANT_X509_LOOKUP: s="SSL_ERROR_WANT_X509_LOOKUP"; break;
            case SSL_ERROR_WANT_ASYNC: s="SSL_ERROR_WANT_ASYNC"; break;
            case SSL_ERROR_WANT_ASYNC_JOB: s="SSL_ERROR_WANT_ASYNC_JOB"; break;
            case SSL_ERROR_SYSCALL: s="SSL_ERROR_SYSCALL"; break;
            case SSL_ERROR_SSL: s="SSL_ERROR_SSL"; break;
        }
        fprintf(stderr, "SSL error: %s\n", s);
        ERR_print_errors_fp(stderr);
        return 3;
    }

    /* Encrypt/Decrypt with private keys -- key should be in ctx 
       use cms_enc and cms_dec */

    /* Construct Get Request */
    hostname[1023] = '\0';
    gethostname(hostname, 1023);
    n = snprintf(obuf, 512, "GET https://%s:%d HTTP/1.0\r\n"
            "Request: END\r\n"
            "User: root\r\n"
            "Password: root\r\n\r\n",
            hostname, s_port); //, user, user, password);

    /* Data communication */
    SSL_write(ssl, obuf, n); //strlen(obuf));
    while ((ilen = SSL_read(ssl, ibuf, sizeof ibuf - 1)) > 0) {
        ibuf[ilen] = '\0';
        printf("%s", ibuf);
    }

    return 0;
}

#include <openssl/ssl.h>
#include <openssl/x509_vfy.h>
#include <openssl/bio.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <netinet/in.h>
#include <openssl/x509_vfy.h>
#include <openssl/conf.h>
#include <unistd.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>


#define READBUF_SIZE 4096
#define WRITEBUF_SIZE 4096
#define 	CHK_ERR(err, s)   if ((err)==-1) { perror(s); exit(1); }

/* Close a current connection and prepare to accept again */
int reset_ssl(SSL **ssl, SSL_CTX *ctx, const char *cert_file,
        int cert_type, const char *priv_key_file, int key_type)
{
    SSL_shutdown(*ssl);
    
    SSL_CTX_free(ctx);
    *ssl = SSL_new(ctx);

    /* Load all certificates, CA Authority, private keys */
    if (SSL_use_certificate_file(*ssl, cert_file, cert_type) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    if (SSL_use_PrivateKey_file(*ssl, priv_key_file, key_type) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }
        return 0;
}

int verify_callback(int ok, X509_STORE_CTX *ctx)
{
    X509 *err_cert;
    int err, depth;
    BIO *bio_err;
    bio_err = BIO_new_fd(fileno(stderr), 0);

    err_cert = X509_STORE_CTX_get_current_cert(ctx);
    err =   X509_STORE_CTX_get_error(ctx);
    depth = X509_STORE_CTX_get_error_depth(ctx);

    fprintf(stderr, "depth=%d ", depth);
    if (err_cert)
    {
        X509_NAME_print_ex(bio_err, X509_get_subject_name(err_cert),
                0, XN_FLAG_ONELINE);
        BIO_puts(bio_err, "\n");

    }
    else
        BIO_puts(bio_err, "<no cert>\n");
    if (!ok)
        fprintf(stderr, "verify error:num=%d:%s\n", err,
                X509_verify_cert_error_string(err));
    switch (err)
    {
        case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
            BIO_puts(bio_err, "issuer= ");
            X509_NAME_print_ex(bio_err, X509_get_issuer_name(err_cert),
                    0, XN_FLAG_ONELINE);
            BIO_puts(bio_err, "\n");
            break;
        case X509_V_ERR_CERT_NOT_YET_VALID:
        case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
            fprintf(stderr, "notBefore=");
            ASN1_TIME_print(bio_err, X509_get_notBefore(err_cert));
            fprintf(stderr, "\n");
            break;
        case X509_V_ERR_CERT_HAS_EXPIRED:
        case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
            fprintf(stderr, "notAfter=");
            ASN1_TIME_print(bio_err, X509_get_notAfter(err_cert));
            fprintf(stderr, "\n");
            break;
        case X509_V_ERR_NO_EXPLICIT_POLICY:
            //policies_print(bio_err, ctx);
            break;
    }
    if (err == X509_V_OK && ok == 2)
        /* print out policies */

        fprintf(stderr, "verify return:%d\n", ok);
    return(ok);
    BIO_free(bio_err);
}

struct sock_info {
    SSL_CTX *ctx;
    SSL *ssl;
    int sock;
    int listen_sock;
};

int setup_ctx(struct sock_info *sock_info,
        const char *cert_file,
        const int cert_type,
        const char *priv_key_file,
        const int key_type,
        const char *CApath,
        int s_port,
        int verify_peer)
{
    SSL_CTX *ctx;
    SSL *ssl;
    int err;

    int flags;
    struct sockaddr_in sa_serv;
    int listen_sock;

    /* Load encryption & hash algorithms for SSL */
    SSL_library_init();
    SSL_load_error_strings();
    ctx = SSL_CTX_new(TLS_server_method());
    ssl = SSL_new(ctx);
    SSL_CTX_set_cipher_list(ctx, "HIGH:!aNULL:!kRSA:!PSK:!SRP:!MD5:!RC4");

    /* Load all certificates, CA Authority, private keys */
    if (SSL_use_certificate_file(ssl, cert_file, cert_type) <= 0) {
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

    if (verify_peer) {
        SSL_CTX_set_verify_depth(ctx,100);
        SSL_CTX_set_verify(ctx, SSL_VERIFY_FAIL_IF_NO_PEER_CERT, verify_callback); 

        /* Peer Certificate Verification */
        /* Set to require peer (client) certificate verification */
        // TODO

    }

    /* Creating and Setting Up the Listening Socket (on the SSL Server) */
    listen_sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    CHK_ERR(listen_sock, "socket");

    /* Ensure the file descriptor is non-blocking, this way we can accept
     * from either port rather than hang on one. */
    flags = fcntl(listen_sock, F_GETFL, 0);
    flags |= SOCK_NONBLOCK;
    if (fcntl(listen_sock, F_SETFL, flags) == -1) {
        perror("Failed to make sockets nonblocking"); 
        exit(1);
    }

    memset(&sa_serv, 0, sizeof(sa_serv));
    sa_serv.sin_family      = AF_INET;
    sa_serv.sin_addr.s_addr = INADDR_ANY;
    sa_serv.sin_port        = htons(s_port);

    err = bind(listen_sock, (struct sockaddr*)&sa_serv,sizeof(sa_serv));
    CHK_ERR(err, "bind");

    /* Receive a TCP connection. */
    err = listen(listen_sock, 5);
    CHK_ERR(err, "listen");

    sock_info->ctx = ctx;
    sock_info->ssl = ssl;
    sock_info->listen_sock = listen_sock;

    return 0;
}

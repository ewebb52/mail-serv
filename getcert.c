/*
 * getcert: request a certificate from the server
 *
 * @user: username
 * @password; password for authentication
 * @server-ip: ip address (usually localhost for testing...)
 */

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
#include <sys/wait.h>

void print_usage(void)
{
    fprintf(stderr, "usage: getcert <username> <password> <server-ip>\n");
}

int main(int argc, char **argv)
{
    SSL_CTX *ctx; SSL *ssl;
    BIO *sbio, *buf_io, *ssl_bio;
    int err; char *s;
    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR)
        exit(1);

    int ilen, n;
    char obuf[512], buf[4096], namebuf[1000], hostname[1024];
    char *user, *password, *server_ip;
    FILE *fd;

    struct sockaddr_in sin;
    int sock, s_port;
    struct hostent *he;

    if (argc != 4) {
        print_usage();
        exit(-1);
    }
    int i;	
    for (i = 0; i < argc; i++) {
        if (strlen(argv[i]) > 100) {
            fprintf(stderr, "Invalid user input.\n");    
            exit(EINVAL);
        }
    }

    user = argv[1];
    password = argv[2];
    server_ip = argv[3];
    s_port = 79996;

    /* Load encryption & hash algorithms for SSL */
    SSL_library_init();
    SSL_load_error_strings();
    ctx = SSL_CTX_new(TLS_client_method());
    SSL_CTX_set_default_verify_dir(ctx);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    ssl = SSL_new(ctx);
    SSL_set_tlsext_host_name(ssl, server_ip);  

    /* Set up a Connecting Client Socket */
    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0) {
        perror("socket");
        return 1;
    }

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons(s_port);
    he = gethostbyname(server_ip);

    memcpy(&sin.sin_addr, (struct in_addr *)he->h_addr, he->h_length);
    if (connect(sock, (struct sockaddr *)&sin, sizeof sin) < 0) {
        perror("connect");
        return 2;
    }

    sbio = BIO_new(BIO_s_socket());
    BIO_set_fd(sbio, sock, BIO_CLOSE);
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

    /* Construct GET request */
    hostname[1023] = '\0';

    /* Create a private key/public key pair for myself */
    int pid, status;
    pid = fork();
    /* Validate that the user exists */
    if (!pid) {
        // TODO this should be in sandbox????
        execl("./scripts/client-key-gen.sh", "./scripts/client-key-gen.sh", user, NULL);

        perror("Execl failed");
        exit(1);

    } else if (pid > 0) {
        pid = wait(&status);
        if (WEXITSTATUS(status) == EINVAL)
            return -1; 

    } else {
        perror("");
        // TODO handle fork failure...
    }   


    unsigned long file_size;
    FILE *fp;
    char csrbuf[4096];
    snprintf(csrbuf, 4095, "clientcsr/%s.csr.pem", user);
    fp = fopen(csrbuf, "rb");
    if (!fp) {
        goto out;
    }
    fseek(fp, 0L, SEEK_END);
    file_size = ftell(fp);

    gethostname(hostname, 1023);
    n = snprintf(obuf, 512, "POST https://%s:%d/%s.cert.pem HTTP/1.0\r\n"
            "Request: GETCERT\r\n"
            "Username: %s\r\n"
            "Password: %s\r\n"
            "Content-Length: %lu\r\n\r\n",
            hostname, s_port, user, user, password, file_size);

    /* Data communication */
    SSL_write(ssl, obuf, n);


    fseek(fp, 0L, SEEK_SET);
    char rbuf[4096];
    while ((n = fread(rbuf, 1, sizeof(rbuf), fp)) > 0) {
        SSL_write(ssl, rbuf, n);
    }

    n = snprintf(obuf, 3, "\r\n");
    SSL_write(ssl, obuf, n); // write from obuf to ssl connection

    buf_io = BIO_new(BIO_f_buffer());
    ssl_bio = BIO_new(BIO_f_ssl());
    BIO_set_ssl(ssl_bio, ssl, BIO_CLOSE);
    BIO_push(buf_io, ssl_bio);

    /* Check for 200 OK response */
    char header[4096];
    if((ilen = BIO_gets(buf_io, header, sizeof header - 1)) < 0) { 
        //TODO
    }

    if (strstr(header + strlen("HTTP/1.0"), "200 OK") == NULL) {
        fprintf(stderr, "%s\n", header);
        while ((ilen = BIO_read(buf_io, header, sizeof header - 1)) > 0) {
            header[ilen] = '\0';
        }
        goto out;
    }

    /* Read remaining header lines... */
    for (;;) {
        if ((ilen = BIO_gets(buf_io, header, sizeof header - 1)) < 0) {
            // TODO error..
        }
        if (strcmp(header, "\r\n") == 0)
            break;
    }

    /* Read in and save the certificate */
    snprintf(namebuf, 999, "%s.cert.pem", user);
    fprintf(stderr, "Client certificate written to %s\n", namebuf);
    fd = fopen(namebuf, "wb");
    if (fd == NULL) {
        //TODO 
        goto out;
    }   

    while ((ilen = BIO_read(buf_io, buf, sizeof buf - 1)) > 0) {
        fwrite(buf, 1, ilen, fd);
    }

    fclose(fd);

out:
    BIO_free(buf_io);
    BIO_free(sbio);
    SSL_shutdown(ssl);
    SSL_free(ssl);
    //   BIO_free(ssl_bio);
    SSL_CTX_free(ctx);
    return 0;
}

#include <stdio.h>
#include <strings.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#include <openssl/pem.h>
#include <openssl/cms.h>

#include <unistd.h>

void print_usage(void)
{
    fprintf(stderr, "usage: sendmsg <username> <client-certificate> <private-key> <server-name>\n");
}

/*
 * Building on prof Bellovin's sample SSL client
 */
/*
   A user logs in with a client-side certificate
   and receives a single encrypted message
   which is then deleted from the server.
   The signature on the message is verified
   and the message is displayed.
   */

int main(int argc, char **argv)
{
    SSL_CTX *ctx;
    SSL *ssl;
    BIO *sbio, *buf_io, *ssl_bio;

    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR)
        exit(1);

    int err; char *s;

    int ilen, rlen;
    char obuf[512];
    int n;
    char *user;
    char *server_ip = argv[4];
    char *private_key;
    struct sockaddr_in sin;
    int sock;
    struct hostent *he;

    /* variables for decryption and verification */
    BIO *in = NULL, *out = NULL, *tbio = NULL, *cont = NULL;
    X509 *rcert = NULL, *cacert = NULL;
    X509_STORE *st = NULL;
    EVP_PKEY *rkey = NULL;
    CMS_ContentInfo *cms = NULL;
    int ret = 1;
    //    int flags = CMS_STREAM || CMS_DETACHED;

    if (argc != 5) {
        print_usage();
        exit(-1);
    }
	for (int i = 0; i < argc; i++) {
		if (strlen(argv[i]) > 100) {
			fprintf(stderr, "Invalid user input.\n");    
			exit(EINVAL);
		}
	}

    user = argv[1];

    user = argv[1];
    //msg = argv[4];
    private_key = argv[3];
    const char *cert_file = argv[2];


    const int cert_type = SSL_FILETYPE_PEM;
    int s_port = 79920;
    char hostname[1024];

    /* Load encryption & hash algorithms for SSL */
    SSL_library_init();
    SSL_load_error_strings();
    ctx = SSL_CTX_new(TLS_client_method());
    SSL_CTX_set_default_verify_dir(ctx);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    ssl = SSL_new(ctx);
    SSL_set_tlsext_host_name(ssl, server_ip);  

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    if (SSL_use_certificate_file(ssl, cert_file, cert_type) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }

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

    /*
       A user logs in with a client-side certificate
       and receives a single encrypted message
       which is then deleted from the server.
       The signature on the message is verified
       and the message is displayed.
       */
    buf_io = BIO_new(BIO_f_buffer());
    ssl_bio = BIO_new(BIO_f_ssl());
    BIO_set_ssl(ssl_bio, ssl, BIO_CLOSE);
    BIO_push(buf_io, ssl_bio);

    /* Decrypt using cms_dec */
    hostname[1023] = '\0';
    gethostname(hostname, 1023);
    n = snprintf(obuf, 512, "GET https://%s:%d/msg HTTP/1.0\r\n"
            "Request: RECVMSG\r\n"
            "User: %s\r\n\r\n",
            hostname, s_port, user);

    /* Data communication */
    SSL_write(ssl, obuf, n); //strlen(obuf));
    /* Check for 200 OK response */
    char header[4096];


    if((ilen = BIO_gets(buf_io, header, sizeof header - 1)) < 0) {
        goto err;
    }

    char *sender;
    char namebuf[4096];
    if (strstr(header + strlen("HTTP/1.0"), "200 OK") == NULL) {
        fprintf(stderr, "%s\n", header);
        while ((ilen = BIO_read(buf_io, header, sizeof header - 1)) > 0) {
            header[ilen] = '\0';
            printf("%s", header);
        }

        goto err;

    } else {
        char *user_prompt, *stray_chars, *len_prompt, *len;
        int l;
        char header[4096];
        char header3[4039];
        char header4[4096];
        /* Get the sender of the message */
        if ((rlen = BIO_gets(buf_io, header, sizeof header - 1)) < 0)
            goto err;
        char *inline_sep = "\r\n ";
        user_prompt = strtok(header, inline_sep);
        sender = strtok(NULL, inline_sep);
        stray_chars = strtok(NULL, inline_sep);

        if (!user_prompt || !sender || stray_chars)
            goto err;

        if (strcmp(user_prompt, "From:") != 0)
            goto err;

       
        if((rlen = BIO_gets(buf_io, header3, sizeof header - 1)) < 0)
            goto err;

        len_prompt = strtok(header3, inline_sep);
        len = strtok(NULL, inline_sep); 
        stray_chars = strtok(NULL, inline_sep);

        if (!len_prompt || !len || stray_chars)
            goto err;    

        //TODO make it check uper and lowercase......!!!
        if (strcmp(len_prompt, "Content-Length:") != 0)
            goto err;

        if (!(l = atoi(len)))
            goto err;

        if((rlen = BIO_gets(buf_io, header4, sizeof header - 1)) < 0)
            goto err;

        if (strcmp(header4, "\r\n") != 0)
            goto err;

        /* Read in and save the certificate */
        fprintf(stderr, "Receiving encrypted message.\n");
        FILE *fd;
        fd = fopen("encr-signed-ret.txt", "w");

        if (fd == NULL) {
            goto err;
        }
        char lineptr[4096];
        int remaining = l;
        int limit; int r;

        while (remaining > 0) {
            limit = remaining > sizeof(lineptr) ? sizeof(lineptr) : remaining;
            //SSL_read(ssl, lineptr, l);
            /* if new line is encountered, break but include it inthe buffer */
            r = BIO_gets(buf_io, lineptr, limit); 
            //            fprintf(stderr, "%d: %s", remaining, lineptr);
            if (r < 0)
                goto err;
            else if (r == 0)
                goto next;
            else {
                remaining -= r;
                fwrite(lineptr, 1, r, fd);
            }   
        }   

next:
        fclose(fd);
        SSL_shutdown(ssl);
        close(sock);
        sock = -1; 

        /* Re-set up a Connecting Client Socket */
        sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock < 0) {
            perror("socket");
            return 1;
        }
    }

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons(s_port);
    memcpy(&sin.sin_addr, (struct in_addr *)he->h_addr, he->h_length);
    if (connect(sock, (struct sockaddr *)&sin, sizeof sin) < 0) {
        perror("connect");
        return 2;
    }

    ssl = SSL_new(ctx);
    /* Load all certificates, CA Authority, private keys */
    if (SSL_use_certificate_file(ssl, cert_file, cert_type) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    SSL_set_tlsext_host_name(ssl, server_ip);
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

    /* Reading recipient certificates from ssl connection,
       write to files locally, save list of filenames in data
       structure recipient_list */
    /* Read in and save the certificate */
    buf_io = BIO_new(BIO_f_buffer());
    ssl_bio = BIO_new(BIO_f_ssl());
    BIO_set_ssl(ssl_bio, ssl, BIO_CLOSE);
    BIO_push(buf_io, ssl_bio);

    /* receive sender certificate, use the user to request their cert */
    n = snprintf(obuf, 512, "GET https://%s:%d/%s.cert.pem HTTP/1.0\r\n"
            "Request: GETMSGCERT\r\n"
            "User: %s\r\n\r\n",
            hostname, s_port, sender, sender);

    SSL_write(ssl, obuf, n);

    /* Check for 200 OK response */

    if((ilen = BIO_gets(buf_io, header, sizeof header - 1)) < 0) {
        //TODO
        
    }

    if (strstr(header + strlen("HTTP/1.0"), "200 OK") == NULL) {
        fprintf(stderr, "%s\n", header);
        while ((ilen = BIO_read(buf_io, header, sizeof header - 1)) > 0) {
            header[ilen] = '\0';
            printf("%s", header);
        }

    } else {
        /* Read remaining header lines... */
        for (;;) {
            if ((ilen = BIO_gets(buf_io, header, sizeof header - 1)) < 0) {
                // TODO error..
            }
            if (strcmp(header, "\r\n") == 0)
                break;
        }

        /* Read in and save the certificate */
        FILE *fd;
        snprintf(namebuf, 999, "%s.cert.pem", sender);
        fprintf(stderr, "Sender certificate written to %s\n", namebuf);
        fd = fopen(namebuf, "wb");
        if (fd == NULL) {
            //TODO
                goto err;
        }

        char buf[4096];
        while ((ilen = BIO_read(buf_io, buf, sizeof buf - 1)) > 0) {
            fwrite(buf, 1, ilen, fd);
        }
        fclose(fd);
    }

    close(sock);
    sock = -1;
    /* Re-set up a Connecting Client Socket */
    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0) {
        perror("socket");
        return 1;
    }

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons(s_port);
    memcpy(&sin.sin_addr, (struct in_addr *)he->h_addr, he->h_length);
    if (connect(sock, (struct sockaddr *)&sin, sizeof sin) < 0) {
        perror("connect");
        return 2;
    }

    ssl = SSL_new(ctx);
    /* Load all certificates, CA Authority, private keys */
    if (SSL_use_certificate_file(ssl, cert_file, cert_type) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    SSL_set_tlsext_host_name(ssl, server_ip);
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

    /* Reading recipient certificates from ssl connection,
       write to files locally, save list of filenames in data
       structure recipient_list */
    /* Read in and save the certificate */
    buf_io = BIO_new(BIO_f_buffer());
    ssl_bio = BIO_new(BIO_f_ssl());
    BIO_set_ssl(ssl_bio, ssl, BIO_CLOSE);
    BIO_push(buf_io, ssl_bio);

    /* receive sender certificate, use the user to request their cert */
    n = snprintf(obuf, 512, "GET https://%s:%d/%s.cert.pem HTTP/1.0\r\n"
            "Request: ROOT\r\n"
            "User: %s\r\n\r\n",
            hostname, s_port, sender, sender);

    SSL_write(ssl, obuf, n);

    /* Check for 200 OK response */

    if((ilen = BIO_gets(buf_io, header, sizeof header - 1)) < 0) {
        //TODO
    }

    if (strstr(header + strlen("HTTP/1.0"), "200 OK") == NULL) {
        fprintf(stderr, "%s\n", header);
        while ((ilen = BIO_read(buf_io, header, sizeof header - 1)) > 0) {
            header[ilen] = '\0';
            printf("%s", header);
        }

    } else {
        /* Read remaining header lines... */
        for (;;) {
            if ((ilen = BIO_gets(buf_io, header, sizeof header - 1)) < 0) {
                // TODO error..
            }
            if (strcmp(header, "\r\n") == 0)
                break;
        }

        /* Read in and save the certificate */
        FILE *fd;
        fprintf(stderr, "Root certificate written to %s\n", "root.cert.pem");
        fd = fopen("root.cert.pem", "wb");
        if (fd == NULL) {
            //TODO
                goto err;
        }

        char buf[4096];
        while ((ilen = BIO_read(buf_io, buf, sizeof buf - 1)) > 0) {
            fwrite(buf, 1, ilen, fd);
        }
        fclose(fd);
    }

    /* verify signature */
    close(sock);
    sock = -1;
    /* Re-set up a Connecting Client Socket */
    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0) {
        perror("socket");
        return 1;
    }

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons(s_port);
    memcpy(&sin.sin_addr, (struct in_addr *)he->h_addr, he->h_length);
    if (connect(sock, (struct sockaddr *)&sin, sizeof sin) < 0) {
        perror("connect");
        return 2;
    }

    ssl = SSL_new(ctx);
    /* Load all certificates, CA Authority, private keys */
    if (SSL_use_certificate_file(ssl, cert_file, cert_type) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    SSL_set_tlsext_host_name(ssl, server_ip);
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

    /* Reading recipient certificates from ssl connection,
       write to files locally, save list of filenames in data
       structure recipient_list */
    /* Read in and save the certificate */
    buf_io = BIO_new(BIO_f_buffer());
    ssl_bio = BIO_new(BIO_f_ssl());
    BIO_set_ssl(ssl_bio, ssl, BIO_CLOSE);
    BIO_push(buf_io, ssl_bio);

    /* receive sender certificate, use the user to request their cert */
    n = snprintf(obuf, 512, "GET https://%s:%d/%s.cert.pem HTTP/1.0\r\n"
            "Request: INTER\r\n"
            "User: %s\r\n\r\n",
            hostname, s_port, sender, sender);

    SSL_write(ssl, obuf, n);

    /* Check for 200 OK response */

    if((ilen = BIO_gets(buf_io, header, sizeof header - 1)) < 0) {
        //TODO
    }

    if (strstr(header + strlen("HTTP/1.0"), "200 OK") == NULL) {
        fprintf(stderr, "%s\n", header);
        while ((ilen = BIO_read(buf_io, header, sizeof header - 1)) > 0) {
            header[ilen] = '\0';
            printf("%s", header);
        }

    } else {
        /* Read remaining header lines... */
        for (;;) {
            if ((ilen = BIO_gets(buf_io, header, sizeof header - 1)) < 0) {
                // TODO error..
            }
            if (strcmp(header, "\r\n") == 0)
                break;
        }

        /* Read in and save the certificate */
        FILE *fd;
        fprintf(stderr, "Intermediate certificate written to %s\n", "intermediate.cert.pem");
        fd = fopen("intermediate.cert.pem", "wb");
        if (fd == NULL) {
            //TODO
                goto err;
        }

        char buf[4096];
        while ((ilen = BIO_read(buf_io, buf, sizeof buf - 1)) > 0) {
            fwrite(buf, 1, ilen, fd);
        }
        fclose(fd);
    }

    /* Set up trusted CA certificate store */

    st = X509_STORE_new();

    /* Read in CA certificate */
    /* this is TODO QUESTION
     * we need access to the CA????? but CA IS PROTECTED ?????? */
    /* authority needs to verify this.... */
    tbio = BIO_new_file(namebuf, "r");

    if (!tbio)
        goto err;

    cacert = PEM_read_bio_X509(tbio, NULL, 0, NULL);

    if (!cacert)
        goto err;

    if (!X509_STORE_add_cert(st, cacert)) {
        goto err;
    }

    //in = BIO_new_file("message-sys/pub/mail/overrich/00001", "r");
    in = BIO_new_file("encr-signed-ret.txt", "r");

    if (!in)
        goto err;
    /* parse message */
    cms = SMIME_read_CMS(in, &cont);

    if (!cms)
        goto err;

    /* File to output verified content to */
    out = BIO_new_file("smver.txt", "w");

    out = BIO_new(BIO_s_mem());
    if (!out)
        goto err;

    STACK_OF(X509) *certss = NULL;
    BIO *heck = NULL, *heck2 = NULL, *heck3 = NULL;
    X509 *heckcert = NULL, *heckcert2 = NULL, *heckcert3 = NULL;
    certss = sk_X509_new_null();
    heck = BIO_new_file(namebuf, "r");
    heckcert = PEM_read_bio_X509(heck, NULL, 0, NULL);
    heck2 = BIO_new_file("intermediate.cert.pem", "r");
    // heck2 = BIO_new_file("ca/intermediate/certs/intermediate.cert.pem", "r");
    // heck3 = BIO_new_file("ca/certs/ca.cert.pem", "r");
    heckcert2 = PEM_read_bio_X509(heck2, NULL, 0, NULL);
    heck3 = BIO_new_file("root.cert.pem", "r");
    
    
    heckcert3 = PEM_read_bio_X509(heck3, NULL, 0, NULL);
    /*
       if (!certss || !sk_X509_push(certss, heckcert3))
       goto err;
       if (!certss || !sk_X509_push(certss, heckcert2))
       goto err;
       */
    if (!certss || !sk_X509_push(certss, heckcert))
        goto err;

    X509_STORE_add_cert(st, heckcert2);
    X509_STORE_add_cert(st, heckcert3);

    if (!CMS_verify(cms, certss, st, cont, out, CMS_NOINTERN)) {
        fprintf(stderr, "Verification Failure\n");
        goto err;
    }

    fprintf(stderr, "Verification Successful\n");

    /* decrypt */

    /* Read in recipient certificate and private key */
    /* this contains both concatenated (write code for this TODO*/
    int pid, status;
    pid = fork();
    /* Validate that the user exists */
    if (!pid) {
        // TODO this should be in sandbox????
        execl("./scripts/pem-gen.sh", "./scripts/pem-gen.sh",
                user, cert_file, private_key, NULL);
        // FIX TODO SENDER RECEIVER
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

    char combined[4096];
    sprintf(combined, "%s.combined.pem", user);
    tbio = BIO_new_file(combined, "r");

    if (!tbio)
        goto err;

    rcert = PEM_read_bio_X509(tbio, NULL, 0, NULL);

    BIO_reset(tbio);


    rkey = PEM_read_bio_PrivateKey(tbio, NULL, 0, NULL);

    if (!rcert || !rkey)
        goto err;

    /* Open S/MIME message to decrypt */

    //TODO 
    //OOOOOOOOOOO
    //in = BIO_new_file("smver.txt", "r");
    //in = BIO_new_file("encr-signed-ret.txt", "r");
    //if (!in)
    //  goto err;

    in = BIO_new(BIO_s_mem());
    char *ptr = NULL;
    long number = BIO_get_mem_data(out, &ptr);
    BIO_write(in, ptr, number);
    /* Parse message */
    BIO *contr = NULL;
    cms = SMIME_read_CMS(in, &contr);


    if (!cms)
        goto err;

    out = BIO_new(BIO_s_mem());
    if (!out)
        goto err;


    /* Decrypt S/MIME message */
    if (!CMS_decrypt(cms, rkey, rcert, contr, out, CMS_STREAM))
        goto err;

    char *decptr = NULL;
    BIO_get_mem_data(out, &decptr);

    fprintf(stderr, "Message from %s:\n%s\n", sender, decptr);
    ret = 0;

err:

    if (ret) {
        fprintf(stderr, "Error Decrypting Data\n");
        ERR_print_errors_fp(stderr);
    }

    CMS_ContentInfo_free(cms);
    X509_free(rcert);
    X509_free(cacert);
    EVP_PKEY_free(rkey);
    BIO_free(in);
    BIO_free(out);
    BIO_free(tbio);
    return ret;
}

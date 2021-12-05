#include <stdio.h>
#include <strings.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/cms.h>
#include <openssl/err.h>
#include <sys/time.h>

#include <sys/types.h>

#include <sys/select.h>
#include <ctype.h>
#include <unistd.h>
#include "list.h"

void print_usage(void)
{
    fprintf(stderr, "usage: sendmsg <user> <client-certificate> <private-key> <file-to-encrypt> <server-hostname> <rcpt> <rcpt> <rcpt> ... \n");
}

/*
 * sendmsg
 *
 * A user logs in with a client-side certificate, sends a list of recipient names,
 * receives their certificates, encrypts the message to those certificates,
 * digitally signs it, and uploads it.
 *
 * @username: user's credentials
 * @certificate: user client-side cert, signed by the server
 *
 */
char *strlower(char *str)
{
    int i = 0;

    while (i < strlen(str)) {
        str[i] = tolower(str[i]);
        i++;
    }

    return NULL;
}

int main(int argc, char **argv)
{
    SSL_CTX *ctx;
    SSL *ssl;
    BIO *sbio, *buf_io, *ssl_bio;
    int err; char *s;

    // ignore SIGPIPE so that we don't terminate when we call
    // send() on a disconnected socket.
    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR)
        exit(1);

    int ilen;
    char obuf[512], buf[4096], namebuf[1000];
    FILE *fd;
    char lineptr[100];
    int n;
    char *user, *private_key;

    struct sockaddr_in sin;
    int sock;
    struct hostent *he;

    /* variables for encryption and signature */
    BIO *in = NULL, *out = NULL, *tbio = NULL;
    STACK_OF(X509) *recips = NULL;
    CMS_ContentInfo *cms = NULL;
    X509 *rcert = NULL, *scert = NULL;;
    EVP_PKEY *skey = NULL;
    int ret = 1;
    int flags = CMS_STREAM;// | CMS_DETACHED;
    char *msg = argv[5];

    if (argc < 7) {
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
    msg = argv[4];
    private_key = argv[3];
    const char *cert_file = argv[2];
    const int cert_type = SSL_FILETYPE_PEM;
    int s_port = 79920;
    char hostname[1024];
    struct Rcpt queue;
    initRcpt(&queue); 

    char* server_ip = argv[5];
    /* Load encryption & hash algorithms for SSL */
    SSL_library_init();
    SSL_load_error_strings();
    ctx = SSL_CTX_new(TLS_client_method());
    SSL_CTX_set_default_verify_dir(ctx);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

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


    /* Get recipient certificates */
    /* Construct Get Request */
    hostname[1023] = '\0';
    gethostname(hostname, 1023);


    // fprintf(stderr, "Input recipient names, one per line, when done, input a control D signal:\n");
    //while (getline(&lineptr, &nl, stdin) != EOF) {
    int m;
    int count = 0;
    for (m = 6; m < argc; m++) {
        // lineptr = argv[m];
        /* Create recipient STACK and add recipient cert to it */
        recips = sk_X509_new_null();
        strncpy(lineptr, argv[m], 101);
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

        int k; 
        for (k = 0; k < strlen(lineptr); k++) 
            if (lineptr[k] == '\n')
                lineptr[k] = '\0';

        //strlower(newstr);
        n = snprintf(obuf, 512, "GET https://%s:%d/%s.cert.pem HTTP/1.0\r\n"
                "Request: GETMSGCERT\r\n"
                "User: %s\r\n\r\n",
                hostname, s_port, lineptr, lineptr);

        SSL_write(ssl, obuf, n);

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

            SSL_shutdown(ssl);
            close(sock);
            sock = -1;

            /* Re-set up a Connecting Client Socket */
            sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (sock < 0) {
                perror("socket");
                return 1;
            }
            sleep(1);


            continue;

        } else {
            /* Add the user to the certificate list */
            //fprintf(stderr, "adding to queue\n", lineptr);
            char *newadd = malloc(strlen(lineptr) + 1);
            memset(newadd, 0, strlen(lineptr) + 1);
            strncpy(newadd, lineptr, strlen(lineptr)); //, lineptr);
            addFront(&queue, newadd);
            count++;
            /* Read remaining header lines... */
            for (;;) {
                if ((ilen = BIO_gets(buf_io, header, sizeof header - 1)) < 0) {
                    // TODO error..
                }
                if (strcmp(header, "\r\n") == 0)
                    break;
            }

            /* Read in and save the certificate */
            snprintf(namebuf, 999, "%s.cert.pem", lineptr);
            fprintf(stderr, "Client certificate written to %s\n", lineptr);
            fd = fopen(namebuf, "wb");
            if (fd == NULL) {
                //TODO 
                continue;
            }   

            while ((ilen = BIO_read(buf_io, buf, sizeof buf - 1)) > 0) {
                fwrite(buf, 1, ilen, fd);
            }
            fclose(fd);
        }

        SSL_shutdown(ssl);
        close(sock);
        sock = -1;

        /* Re-set up a Connecting Client Socket */
        sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock < 0) {
            perror("socket");
            return 1;
        }
        sleep(1);
        // }
        /*
           if (count <= 0) {
           fprintf(stderr, "No valid recipients\n");
           goto err;

           }
           */
        /* Get root and intermediate certificatesion */
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
                hostname, s_port, user, user);

        SSL_write(ssl, obuf, n);

        /* Check for 200 OK response */

        //char header[4096];
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
                continue;
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
                hostname, s_port, user, user);

        SSL_write(ssl, obuf, n);

        /* Check for 200 OK response */

        if((ilen = BIO_gets(buf_io, header, sizeof header - 1)) < 0) {
            //TODO
        }

        if (strstr(header + strlen("HTTP/1.0"), "200 OK") == NULL) {
            fprintf(stderr, "%s\n", header);
            while ((ilen = BIO_read(buf_io, header, sizeof header - 1)) > 0) {
                header[ilen] = '\0';
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
                continue;
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
        /* Encrypt message with cms_encrypt -- key should be in ctx */
        /* need a loop for all recipient certs here */
        int i = 0;
        /*  if (queue.size > 0) {
            struct Node *node = queue.head;
            while (node != NULL) {
            if (!node->data) {
            node = node->next;
            continue;
            }
            */          char certbuf[strlen(".cert.pem") + 1 + strlen(argv[m])];//(char *)node->data)];
        snprintf(certbuf, 999, "%s.cert.pem", argv[m]);
        //fprintf(stderr, "USING %s\n", cerbuf);
        tbio = BIO_new_file(certbuf, "r");
        i++;         
        //node = node->next;


        /* Read in recipient certificate */
        if (!tbio)
            goto err;

        rcert = PEM_read_bio_X509(tbio, NULL, 0, NULL);

        if (!rcert)
            goto err;

        if (!recips || !sk_X509_push(recips, rcert))
            goto err;

        /*
         * sk_X509_pop_free will free up recipient STACK and its contents so set
         * rcert to NULL so it isn't freed up twice.
         */
        rcert = NULL;

        /* Open content being encrypted */
        in = BIO_new_file(msg, "r");
        if (!in)
            goto err;

        /* encrypt content */
        cms = CMS_encrypt(recips, in, EVP_des_ede3_cbc(), flags);
        if (!cms)
            goto err;

        // TODO THIS NEEDS TO HAPPEN ask TAs if its ok if its not protected
        out = BIO_new_file("smencr.txt", "w");
        if (!out)
            goto err;

        /* Write out S/MIME message */
        if (!SMIME_write_CMS(out, cms, in, flags))
            goto err;


        int pid, status;
        pid = fork();
        /* Validate that the user exists */
        if (!pid) {
            // TODO this should be in sandbox????
            execl("./scripts/pem-gen.sh", "./scripts/pem-gen.sh",
                    user, cert_file, private_key, NULL);

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


        //TODO replace with correct certificate and SIGN it....
        // this will be a a certificate and key
        // make function that concatenates cert and key
        char combined[1000];
        sprintf(combined, "%s.combined.pem", user); 
        tbio = BIO_new_file(combined, "r");
        scert = PEM_read_bio_X509(tbio, NULL, 0, NULL);
        if (!scert)
            goto err;

        BIO_reset(tbio);

        //TODO include my private key
        skey = PEM_read_bio_PrivateKey(tbio, NULL, 0, NULL);
        if (!skey)
            goto err;

        /* Open content being signed */
        in = BIO_new_file("smencr.txt", "r");
        if (!in)
            goto err;
        STACK_OF(X509) *certss = NULL;
        //BIO *heck = NULL,
        BIO *heck2 = NULL, *heck3 = NULL;
        //X509 *heckcert = NULL, 
        X509 *heckcert2 = NULL, *heckcert3 = NULL;
        certss = sk_X509_new_null();
        //  heck = BIO_new_file(namebuf, "r");
        //heckcert = PEM_read_bio_X509(heck, NULL, 0, NULL);

        //       heck2 = BIO_new_file("ca/intermediate/certs/intermediate.cert.pem", "r");
        //  heck3 = BIO_new_file("ca/certs/ca.cert.pem", "r");

        heck2 = BIO_new_file("intermediate.cert.pem", "r");
        heckcert2 = PEM_read_bio_X509(heck2, NULL, 0, NULL);
        heck3 = BIO_new_file("root.cert.pem", "r");
        heckcert3 = PEM_read_bio_X509(heck3, NULL, 0, NULL);

        if (!certss || !sk_X509_push(certss, heckcert3))
            goto err;
        if (!certss || !sk_X509_push(certss, heckcert2))
            goto err;
        /* Sign content */
        cms = CMS_sign(scert, skey, certss, in, flags);
        if (!cms)
            goto err;


        out = BIO_new(BIO_s_mem());
        //out = BIO_new_file("encr-signed.txt", "w");
        if (!out)
            goto err;

        if (!(flags & CMS_STREAM))
            BIO_reset(in);

        /* Write out S/MIME message */
        if (!SMIME_write_CMS(out, cms, in, flags))
            goto err;

        ret = 0;

        //BUF_MEM *bm = NULL;
        /* need to sign the message */
        //unsigned long file_size;
        //FILE *fp;

        char *help;
        long length = BIO_get_mem_data(out, &help);
        /*if (queue.size <= 0)
          goto out;


          fprintf(stderr, "here now\n");
          struct Node *node = queue.head;
          while (node != NULL) {
          if (!node->data)
          continue;
          */
        memset(&sin, 0, sizeof(sin));
        sin.sin_family = AF_INET;
        sin.sin_port = htons(s_port);
        memcpy(&sin.sin_addr, (struct in_addr *)he->h_addr, he->h_length);
        if (connect(sock, (struct sockaddr *)&sin, sizeof sin) < 0) {
            perror("ERROR: connect");
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

        /* Data communication - sending encrypted message from out to ssl connection*/
        memset(obuf, 0, sizeof(obuf));
        n = snprintf(obuf, 512, "POST https://%s:%d/msg HTTP/1.0\r\n"
                "Request: SENDMSG\r\n"
                "User: %s\r\n"
                "Rcpt: %s\r\n"
                "Content-Length: %lu\r\n",
                hostname, s_port, user, argv[m], length);
        SSL_write(ssl, obuf, n);

        // file to upload is encr-signed.txt
        /*
        //	Either have a huge string with the mesage or read in message from file line by line here
        n = snprintf(obuf + strlen(obuf), sizeof(obuf), "")
        */
        n = snprintf(obuf, 3, "\r\n");

        SSL_write(ssl, obuf, n); // write from obuf to ssl connection
        /* // don't need this part as we are POSTing here
           while ((ilen = SSL_read(ssl, ibuf, sizeof ibuf - 1)) > 0) {
           ibuf[ilen] = '\0';
           printf("%s", ibuf);
           }
           */

        /* Read the file line by line and send */
        char rbuf[4096];
        FILE *fd2 = fopen("encr-signed.txt", "wb");
        if (fd2 == NULL) {
            goto err;
        }
        memset(rbuf, 0, sizeof(rbuf));
        //BIO_reset(out);
        //fprintf(stderr, "here\n");
        /*while ((n = fread(rbuf, 1, sizeof(rbuf) - 1, fd2)) > 0) {
          fprintf(stderr, "%d", n);
          SSL_write(ssl, rbuf, n);
          memset(rbuf, 0, sizeof(rbuf));
          }
          */
        SSL_write(ssl, help, length);
        fwrite(help, 1, length, fd2);
        //        n = snprintf(obuf, 3, "\r\n");
        //        SSL_write(ssl, obuf, n); // write from obuf to ssl connection


        /* Read the response */
        /* Check for 200 OK response */
        //char header[4096];

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
            /* Add the user to the certificate list */
            /* Read remaining header lines... */
            fprintf(stderr, "Message sent to %s\n", argv[m]);//(char *)node->data);
            for (;;) {
                if ((ilen = BIO_gets(buf_io, header, sizeof header - 1)) < 0) {
                    // TODO error..
                }
                if (strcmp(header, "\r\n") == 0)
                    break;
            }

        }

        SSL_shutdown(ssl);
        close(sock);
        sock = -1;

        /* Re-set up a Connecting Client Socket */
        sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock < 0) {
            perror("socket");
            return 1;
        }
        sleep(1);
        //      node = node->next;
}

fprintf(stderr, "Encrypted Data to Server\n");
goto out;

err:

if (ret) {
    fprintf(stderr, "Error Encrypting Data\n");
    ERR_print_errors_fp(stderr);
}
out:

CMS_ContentInfo_free(cms);
X509_free(rcert);
EVP_PKEY_free(skey);
sk_X509_pop_free(recips, X509_free);
BIO_free(in);
BIO_free(out);
BIO_free(tbio);
return ret;

//    return 0;
}

#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/poll.h>
#include "handler.h"
#include <sys/signalfd.h>
#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

int main(int argc, char *argv[])
{
    int err; char *s;

    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR)
        exit(1);

    struct sockaddr_in sa_cli;
    int sock;
    socklen_t client_len;
    int s_port_pass = 79996;
    int s_port_cert = 79920;

    const char *cert_file = "ca/intermediate/certs/server.cert.pem";
    const int cert_type = SSL_FILETYPE_PEM;
    const char *priv_key_file = "ca/intermediate/private/server.key.pem";
    const int key_type = SSL_FILETYPE_PEM;
    const char *CApath = "ca/intermediate/certs/";

    /* SSL BIOs */
    BIO *sbio, *buf_io, *ssl_bio;

    /* Message parsing */
    int rlen;
    char request[READBUF_SIZE]; char header[READBUF_SIZE];
    char *method, *stray_chars, *url, *http, *request_type;
    char *inline_sep = " \r\n \t"; 

    /* SSL Connection structs */
    int status;
    struct pollfd fds[2];
    int nfds = 2, i, ready;
    struct sock_info sock_info_cert;
    struct sock_info sock_info_pass;
    struct sock_info sock_info_curr;

    /* Set up SSL connections for clients */ 
    if (setup_ctx(&sock_info_pass, cert_file, cert_type,
                priv_key_file, key_type, CApath,
                s_port_pass, 0 /* Do not verify peer */)) {
        exit(1);
    }

    if (setup_ctx(&sock_info_cert, cert_file, cert_type,
                priv_key_file, key_type, CApath,
                s_port_cert, 1 /* Verify peer */)) {
        exit(1);
    }

    memset(fds, 0 , sizeof(fds));
    fds[0].fd = sock_info_pass.listen_sock;
    fds[0].events = POLLIN;
    fds[1].fd = sock_info_cert.listen_sock;
    fds[1].events = POLLIN;

    for (;;) {


        ready = poll(fds, nfds, -1 /* Infinite timeout... */);

        if (ready < 0) {
            perror("poll() failed");
            exit(1);
        }
        for (i = 0; i < nfds; i++) {
            if (!fds[i].revents) {
                continue;
            }
            if (!(fds[i].revents & POLLIN)) {
                continue;
            }
            break;
        }

        memset(&sa_cli, 0, sizeof(sa_cli));
        memset(&client_len, 0, sizeof(client_len));        
        sock = accept(fds[i].fd, (struct sockaddr*)&sa_cli, &client_len);
        if (sock < 0) {
            if (errno != EWOULDBLOCK) {
                perror("accept() failed");
                exit(1);
            }
            break;
        }

        fprintf(stderr, "Accepting connection.\n"); //%x, port %x\n", 
        //sa_cli.sin_addr.s_addr, sa_cli.sin_port);

        if (i == 0) {
            sock_info_curr = sock_info_pass;
        } else { 
            sock_info_curr = sock_info_cert;
        } 

        sbio = BIO_new(BIO_s_socket());
        BIO_set_fd(sbio, sock, BIO_NOCLOSE);
        SSL_set_bio(sock_info_curr.ssl, sbio, sbio);

        if ((err = SSL_accept(sock_info_curr.ssl)) != 1) {
            switch (SSL_get_error(sock_info_curr.ssl, err)) {
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
        }

        buf_io = BIO_new(BIO_f_buffer());    
        ssl_bio = BIO_new(BIO_f_ssl());
        BIO_set_ssl(ssl_bio, sock_info_curr.ssl, BIO_CLOSE);
        BIO_push(buf_io, ssl_bio);

        /* Read the headers line by line */
        if((rlen = BIO_gets(buf_io, header, sizeof header - 1)) < 0) {
            status = 400;
            send_status(sock_info_curr.ssl, sock, status);
            goto close_connection;
        }

        method = strtok(header, inline_sep);
        url = strtok(NULL, inline_sep); 
        http = strtok(NULL, inline_sep);
        stray_chars = strtok(NULL, inline_sep);

        if (!method || !url || !http || stray_chars) {
            status = 501;    
            send_status(sock_info_curr.ssl, sock, status);
            goto close_connection;
        }

        if (strcmp(method, "GET") != 0 && strcmp(method, "POST") != 0) {
            status = 501;    
            send_status(sock_info_curr.ssl, sock, status);
            goto close_connection;
        }
        if (strcmp(http, "HTTP/1.0") != 0 &&
                strcmp(http, "HTTP/1.1") != 0) {
            status = 501;    
            send_status(sock_info_curr.ssl, sock, status);
            goto close_connection;
        }

        /* Read all header lines and parse them appropriately */
        if((rlen = BIO_gets(buf_io, request, sizeof header - 1)) < 0) {
            status = 400;
            send_status(sock_info_curr.ssl, sock, status);
            goto close_connection;
        }

        if (strncmp(request, "Request: ", strlen("Request: ")) != 0) {
            status = 400;    
            send_status(sock_info_curr.ssl, sock, status);
            goto close_connection;
        }

        strtok(request, inline_sep);
        request_type = strtok(NULL, inline_sep);
        stray_chars = strtok(NULL, inline_sep);
        if (!request_type || stray_chars) {
            status = 501;    
            send_status(sock_info_curr.ssl, sock, status);
            goto close_connection;
        }

        switch (GET_METHOD(method, request + strlen("Request: "), i)) {
            case GETCERT:
                if ((status = get_cert(buf_io, sock_info_curr.ssl, sock))) {
                    send_status(sock_info_curr.ssl, sock, status);
                    goto close_connection;
                }

                goto close_connection;

            case CHANGEPW:
                if ((status = change_password(buf_io, sock_info_curr.ssl, sock))) {
                    send_status(sock_info_curr.ssl, sock, status);
                    fprintf(stderr, "Authentication failed\n");
                    goto close_connection;

                }

                goto close_connection;

            case GETMSGCERT:
                if ((status = get_msg_cert(buf_io, sock_info_curr.ssl, sock)) != 0) {
                    send_status(sock_info_curr.ssl, sock, status);
                    goto close_connection;
                }

                goto close_connection;

            case SENDMSG:
                if ((status = store_msg(buf_io, sock_info_curr.ssl, sock)) != 0) {
                    send_status(sock_info_curr.ssl, sock, status);
                    goto close_connection;
                }
                goto close_connection;

            case RECVMSG:
                if ((status = recv_msg(buf_io, sock_info_curr.ssl, sock)) != 0) {
                    send_status(sock_info_curr.ssl, sock, status);
                    goto close_connection;
                }
                goto close_connection;

            case INTER:
                if ((status = get_inter_cert(buf_io, sock_info_curr.ssl, sock)) != 0) {
                    send_status(sock_info_curr.ssl, sock, status);
                    goto close_connection;
                }
                goto close_connection;

            case ROOT:
                if ((status = get_root_cert(buf_io, sock_info_curr.ssl, sock)) != 0) {
                    send_status(sock_info_curr.ssl, sock, status);
                    goto close_connection;
                }
                goto close_connection;

            case END:
                goto out;

            default:
                // FOR NOW.... TODO
                status = 400;
                send_status(sock_info_curr.ssl, sock, status);
                goto close_connection;
                continue;
        }

close_connection:
        BIO_free(buf_io);
        BIO_free(sbio);

        if (i == 0) {
            reset_ssl(&(sock_info_pass.ssl), sock_info_pass.ctx,
                    cert_file, cert_type, priv_key_file, key_type);
        } else {
            reset_ssl(&(sock_info_cert.ssl), sock_info_cert.ctx,
                    cert_file, cert_type, priv_key_file, key_type);
        }
        //BIO_free_all(buf_io);
        close(sock); 

    } 
out:
    /* Closing an SSL Connection */
    BIO_free(buf_io);
    BIO_free(sbio);
    SSL_shutdown(sock_info_pass.ssl);
    SSL_shutdown(sock_info_cert.ssl);
    SSL_free(sock_info_pass.ssl);
    SSL_free(sock_info_cert.ssl);
    //   BIO_free(ssl_bio);
    SSL_CTX_free(sock_info_pass.ctx);    
    SSL_CTX_free(sock_info_cert.ctx);    
}

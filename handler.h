#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/poll.h>
#include <dirent.h>
#include <ctype.h>

#include "server.h"

#define GETCERT 1
#define CHANGEPW 2
#define SENDMSG 3
#define RECVMSG 4
#define GETMSGCERT 5
#define END 6
#define ROOT 7
#define INTER 8
int strlower(char *str)
{
    int i = 0;

    while (i < strlen(str)) {
        if (isdigit(str[i]))
            continue;

        if (str[i] == '.' || str[i] == '\\' || str[i] == '*')
            return 1;

        str[i] = tolower(str[i]);
        i++;
    }

    return 0;
}

/* GETCERT and CHANGEPW can only be valid
 * If they are connecting through sock 0
 * As indexed in the array of listening sockets, 
 * because they connected without a cert.
 *
 * SEND/RECVMSG are only valid through sock
 * indexed at 1
 */
int GET_METHOD(char *verb, char *method, int sock)
{
    if (strcmp(verb, "POST") == 0 && strcmp(method, "GETCERT") == 0 &&
            sock == 0) {
        return GETCERT;
    } else if (strcmp(verb, "POST") == 0 && strcmp(method, "CHANGEPW") == 0 &&
            sock == 0) {
        return CHANGEPW;
    } else if (strcmp(verb, "POST") == 0 && strcmp(method, "SENDMSG") == 0 && sock == 1) {
        return SENDMSG;
    } else if (strcmp(verb, "GET") == 0 && strcmp(method, "RECVMSG") == 0 && sock == 1) {
        return RECVMSG;
    } else if (strcmp(verb, "GET") == 0 && strcmp(method, "GETMSGCERT") == 0 && sock == 1) {
        return GETMSGCERT;
    } else if (strcmp(verb, "GET") == 0 && strcmp(method, "END") == 0 && sock == 0) {
        return END;
    } else if (strcmp(verb, "GET") == 0 && strcmp(method, "ROOT") == 0 && sock == 1) {
        return ROOT;
    } else if (strcmp(verb, "GET") == 0 && strcmp(method, "INTER") == 0 && sock == 1) {
        return INTER;
    } else {
        return -1;
    }
}

int send_status_norn(SSL *ssl, int sock, int status)
{
    char buf[1000], body[1000];
    char *msg;

    switch(status) {
        case 200: 
            msg = "OK";
            break;
        case 501:
            msg = "Not Implemented";
            break;
        case 400:
            msg = "Bad Request";
            break;
        default:
            msg = "UH OH"; //TODO

    }

    sprintf(buf, "HTTP/1.0 %d ", status);
    strcat(buf, msg);
    strcat(buf, "\r\n");

    if (status != 200) {
        strcat(buf, "\r\n");
        sprintf(body,
                "<html><body>\n"
                "<h1>%d %s</h1>\n"
                "</body></html>\n",
                status, msg);
        strcat(buf, body);
    }

    SSL_write(ssl, buf, strlen(buf));
    return 0;
}
int send_status(SSL *ssl, int sock, int status)
{
    char buf[1000], body[1000];
    char *msg;

    switch(status) {
        case 200: 
            msg = "OK";
            break;
        case 501:
            msg = "Not Implemented";
            break;
        case 400:
            msg = "Bad Request";
            break;
        default:
            msg = "UH OH"; //TODO

    }

    sprintf(buf, "HTTP/1.0 %d ", status);
    strcat(buf, msg);
    strcat(buf, "\r\n");
    //    strcat(buf, "\r\n");

    if (status != 200) {
        sprintf(body,
                "<html><body>\n"
                "<h1>%d %s</h1>\n"
                "</body></html>\n",
                status, msg);
        strcat(buf, body);
    }

    SSL_write(ssl, buf, strlen(buf));
    return 0;
}

int check_user(int check_pass, char *file, char *user, char *old_pass) 
{
    int pid1, pid2;
    int status1, status2;

    pid1 = fork();

    /* Validate that the user exists */
    if (!pid1) {
        // TODO this should be in sandbox????
        if (setgid(getgid()) == -1) {
            /* handle error condition */
        }
        if (setuid(getuid()) == -1) {
            /* handle error condition */
        }

        execl("./check-user", "./check-user",
                user, NULL);

        perror("Execl failed");
        exit(1);

    } else if (pid1 > 0) {
        pid1 = wait(&status1);
        if (WEXITSTATUS(status1) == EINVAL)
            return -1; 

    } else {
        perror("");
        // TODO handle fork failure...
    }

    if (!check_pass)
        return 0;

    /* Check that the original password is correct */
    pid2 = fork();
    if (!pid2) {
        // TODO this should be in sandbox????
        execl("./check-password", "./check-password",
                file, user, old_pass, NULL);

        perror("Execl failed");
        exit(1);

    } else if (pid2 > 0) {
        pid2 = wait(&status2);
        if (WEXITSTATUS(status2) == EINVAL)
            return -1; 

    } else {
        perror("");
        // TODO handle fork failure...
    }
    return 0;
}

int get_msg_cert(BIO *buf_io, SSL *ssl, int sock)
{
    int rlen, n;

    char header[1008], namebuf[1000], buf[4096];
    char header4[1008];

    char *user_prompt, *stray_chars;
    char *user;

    FILE *fd;
    char *inline_sep = " \r\n";

    if ((rlen = BIO_gets(buf_io, header, sizeof header - 1)) < 0)
        return 400;

    user_prompt = strtok(header, inline_sep);
    user = strtok(NULL, inline_sep); 
    stray_chars = strtok(NULL, inline_sep);

    if (!user_prompt || !user || stray_chars)
        return 501;    

    if (strcmp(user_prompt, "User:") != 0)
        return 501;

    if ((rlen = BIO_gets(buf_io, header4, sizeof header - 1)) < 0)
        return 400;

    if (strcmp(header4, "\r\n") != 0)
        return 501;

    if (check_user(0, user, user, NULL))
        return 501;

    /* Read in and send the certificate */
    snprintf(namebuf, 999, "message-sys/priv/%s/cert/%s.cert.pem", user, user);
    fd = fopen(namebuf, "rb");
    if (fd == NULL) {
        return 400;
    }

    send_status(ssl, sock, 200);
    fseek(fd, 0L, SEEK_END);
    unsigned long file_size = ftell(fd);
    fseek(fd, 0L, SEEK_SET);
    char content[4001];
    n = snprintf(content, 4000, "Content-Length: %ld\r\n\r\n", file_size);
    SSL_write(ssl, content, n);

    while ((n = fread(buf, 1, sizeof(buf), fd)) > 0) {
        SSL_write(ssl, buf, n);
    }

    fclose(fd);
    return 0;
}

int change_password(BIO *buf_io, SSL *ssl, int sock)
{
    int pid, status;

    int rlen, l, n;
    char header[1008], header2[1008], header3[1008], header4[1008];
    char namebuf[1000], buf[4096];
    char *user_prompt, *pass_prompt, *len_prompt, *len, *stray_chars;
    char *user, *old_pass, *new_pass;
    char *inline_sep = " \r\n";
    FILE *fd;

    if ((rlen = BIO_gets(buf_io, header, sizeof header - 1)) < 0)
        return 400;

    user_prompt = strtok(header, inline_sep);
    user = strtok(NULL, inline_sep); 
    stray_chars = strtok(NULL, inline_sep);

    if (!user_prompt || !user || stray_chars)
        return 501;    

    if (strcmp(user_prompt, "Username:") != 0)
        return 501;

    if((rlen = BIO_gets(buf_io, header2, sizeof header - 1)) < 0)
        return 400;

    pass_prompt = strtok(header2, inline_sep);
    old_pass = strtok(NULL, inline_sep); 
    stray_chars = strtok(NULL, inline_sep);

    if (!pass_prompt || !old_pass || stray_chars)
        return 501;    

    if (strcmp(pass_prompt, "Password:") != 0)
        return 501;

    char headerf[4096];
    if((rlen = BIO_gets(buf_io, headerf, sizeof header - 1)) < 0)
        return 400;

    pass_prompt = strtok(headerf, inline_sep);
    new_pass = strtok(NULL, inline_sep); 
    stray_chars = strtok(NULL, inline_sep);

    if (!pass_prompt || !old_pass || stray_chars)
        return 501;    

    if (strcmp(pass_prompt, "NewPassword:") != 0)
        return 501;
    if((rlen = BIO_gets(buf_io, header3, sizeof header - 1)) < 0)
        return 400;

    len_prompt = strtok(header3, inline_sep);
    len = strtok(NULL, inline_sep); 
    stray_chars = strtok(NULL, inline_sep);

    if (!len_prompt || !len || stray_chars)
        return 501;    

    //TODO make it check uper and lowercase......!!!
    strlower(len_prompt);
    if (strcmp(len_prompt, "content-length:") != 0)
        return 501;

    if (!(l = atoi(len)))
        return 400;
    if (l <= 0)
        return 400;

    if (l <= 0)
        return 400;
    if((rlen = BIO_gets(buf_io, header4, sizeof header - 1)) < 0)
        return 400;

    if (strcmp(header4, "\r\n") != 0)
        return 501;

    if (check_user(1, user, user, old_pass))
        return 501;

    /* return error if there are messages pending */
    char newpath[4069];
    snprintf(newpath, 4065, "message-sys/pub/mail/%s", user);
    DIR * dr = opendir(newpath);
    struct dirent *de;

    /* Get tail in current directory */
    int count = -1;

    while ((de = readdir(dr)) != NULL)
        count++;

    closedir(dr);
    if (count > 1)
        return 400;

    /* Update the password file */
    pid = fork();
    if (!pid) {
        // TODO this should be in sandbox????
        execl("./hash-password", "./hash-password",
                user, user, new_pass, NULL);
        perror("Execl failed");
        exit(1);

    } else if (pid > 0) {
        pid = wait(&status);
        if (WEXITSTATUS(status) == EINVAL)
            return 400; //TODO some other invalid....

    } else {
        perror("");
        // TODO handle fork failure...
    }

    /* Read in the csr */
    snprintf(namebuf, 999, "message-sys/tmp/%s.csr.pem", user);
    FILE *saveme = fopen(namebuf, "wb");
    if (saveme == NULL) {
        return 400;
    }

    char lineptr[4096];
    int remaining = l;
    int r; int limit;
    while (remaining > 0) {
        limit = remaining > sizeof(lineptr) ? sizeof(buf) : remaining;
        //SSL_read(ssl, lineptr, l);
        /* if new line is encountered, break but include it inthe buffer */
        r = BIO_gets(buf_io, lineptr, limit);
        if (r < 0)
            return 400;
        else if (r == 0)
            goto next;
        else {
            remaining -= r;
            fwrite(lineptr, 1, r, saveme);
        }
    }
next:
    fclose(saveme);

    /* Create a certificate for the user */
    pid = fork();
    if (!pid) {
        // TODO this should be in sandbox????
        execl("./scripts/run-revoke.exp", "./scripts/run-revoke.exp", 
                user, NULL);
        perror("Execl failed");
        exit(1);

    } else if (pid > 0) {
        pid = wait(&status);
        if (WEXITSTATUS(status) == EINVAL)
            return 400; //TODO some other invalid....

    } else {
        perror("");
        // TODO handle fork failure...
    }

    /* Create a certificate for the user */
    pid = fork();
    if (!pid) {
        // TODO this should be in sandbox????
        execl("./scripts/run-make-cert.exp", "./scripts/run-make-cert.exp", 
                new_pass, user, NULL);
        perror("Execl failed");
        exit(1);

    } else if (pid > 0) {
        pid = wait(&status);
        if (WEXITSTATUS(status) == EINVAL)
            return 400; //TODO some other invalid....

    } else {
        perror("");
        // TODO handle fork failure...
    }

    /* Read in and send the certificate */
    snprintf(namebuf, 999, "message-sys/priv/%s/cert/%s.cert.pem", user, user);
    fd = fopen(namebuf, "rb");
    if (fd == NULL) {
        //TODO 
        return 400;
    }

    send_status(ssl, sock, 200);
    SSL_write(ssl, "\r\n", 2);
    while ((n = fread(buf, 1, sizeof(buf), fd)) > 0) {
        SSL_write(ssl, buf, n);
    }

    fclose(fd);
    return 0;
}

int get_cert(BIO *buf_io, SSL *ssl, int sock)
{
    int pid, status;
    int rlen, n;

    char header[1008], namebuf[1000], buf[4096];
    char header4[1008], header2[1008], header3[1008];

    char *user_prompt, *pass_prompt, *stray_chars;
    char *user, *old_pass, *len_prompt, *len;

    FILE *fd;
    char *inline_sep = " \r\n";
    if ((rlen = BIO_gets(buf_io, header, sizeof header - 1)) < 0)
        return 400;

    user_prompt = strtok(header, inline_sep);
    user = strtok(NULL, inline_sep); 
    stray_chars = strtok(NULL, inline_sep);

    if (!user_prompt || !user || stray_chars)
        return 501;    

    if (strcmp(user_prompt, "Username:") != 0)
        return 501;

    if((rlen = BIO_gets(buf_io, header2, sizeof header - 1)) < 0)
        return 400;

    pass_prompt = strtok(header2, inline_sep);
    old_pass = strtok(NULL, inline_sep); 
    stray_chars = strtok(NULL, inline_sep);

    if (!pass_prompt || !old_pass || stray_chars)
        return 501;    

    if (strcmp(pass_prompt, "Password:") != 0)
        return 501;

    if((rlen = BIO_gets(buf_io, header3, sizeof header - 1)) < 0)
        return 400;
    len_prompt = strtok(header3, inline_sep);
    len = strtok(NULL, inline_sep); 
    stray_chars = strtok(NULL, inline_sep);

    if (!len_prompt || !len || stray_chars)
        return 501;    

    //TODO make it check uper and lowercase......!!!
    strlower(len_prompt);
    if (strcmp(len_prompt, "content-length:") != 0)
        return 501;

    int l;
    if (!(l = atoi(len)))
        return 501;
    if (l <= 0)
        return 400;

    if((rlen = BIO_gets(buf_io, header4, sizeof header - 1)) < 0)
        return 400;

    if (strcmp(header4, "\r\n") != 0)
        return 501;

    if (check_user(1, user, user, old_pass))
        return 501;


    /* Read in the CSR for the user */

    snprintf(namebuf, 999, "message-sys/tmp/%s.csr.pem", user);
    FILE *saveme = fopen(namebuf, "wb");
    if (saveme == NULL) {
        return 400;
    }

    char lineptr[4096];
    int remaining = l;
    int limit; int r;
    while (remaining > 0) {
        limit = remaining > sizeof(lineptr) ? sizeof(buf) : remaining;
        //SSL_read(ssl, lineptr, l);
        /* if new line is encountered, break but include it inthe buffer */
        r = BIO_gets(buf_io, lineptr, limit);
        if (r < 0)
            return 400;
        else if (r == 0)
            goto next;
        else {
            remaining -= r;
            fwrite(lineptr, 1, r, saveme);
        }
    }
next:
    fclose(saveme);

    /* Read in and send the certificate */
    snprintf(namebuf, 999, "message-sys/priv/%s/cert/%s.cert.pem", user, user);

    fd = fopen(namebuf, "rb");
    if (fd != NULL) {
        fclose(fd);
        return 400;
    }

    /* Create a certificate for the user */
    pid = fork();
    if (!pid) {
        // TODO this should be in sandbox????
        execl("./scripts/run-make-cert.exp", "./scripts/run-make-cert.exp", 
                old_pass, user, NULL);
        perror("Execl failed");
        exit(1);

    } else if (pid > 0) {
        pid = wait(&status);
        if (WEXITSTATUS(status) == EINVAL)
            return 400; //TODO some other invalid....

    } else {
        perror("");
        // TODO handle fork failure...
    }

    /* Read in and send the certificate */
    snprintf(namebuf, 999, "message-sys/priv/%s/cert/%s.cert.pem", user, user);

    fd = fopen(namebuf, "rb");
    if (fd == NULL) {
        //TODO 
        return 400;
    }

    send_status(ssl, sock, 200);
    SSL_write(ssl, "\r\n", 2);
    while ((n = fread(buf, 1, sizeof(buf), fd)) > 0) {
        SSL_write(ssl, buf, n);
    }

    fclose(fd);
    return 0;
}

int store_msg(BIO *buf_io, SSL *ssl, int sock)
{
    int rlen, l;

    char header[1008], header3[1008];
    char header4[1008], rcptheader[1008];

    char *user_prompt, *stray_chars, *len_prompt;
    char *user, *len, *rcpt, *rcpt_prompt;

    char *inline_sep = " \r\n";

    if ((rlen = BIO_gets(buf_io, header, sizeof header - 1)) < 0)
        return 400;

    user_prompt = strtok(header, inline_sep);
    user = strtok(NULL, inline_sep); 
    stray_chars = strtok(NULL, inline_sep);

    if (!user_prompt || !user || stray_chars)
        return 501;    

    if (strcmp(user_prompt, "User:") != 0)
        return 501;

    if (check_user(0, user, user, NULL))
        return 501;

    if ((rlen = BIO_gets(buf_io, rcptheader, sizeof header - 1)) < 0)
        return 400;

    rcpt_prompt = strtok(rcptheader, inline_sep);
    rcpt = strtok(NULL, inline_sep); 
    stray_chars = strtok(NULL, inline_sep);

    if (!rcpt_prompt || !rcpt || stray_chars)
        return 501;    

    if (strcmp(rcpt_prompt, "Rcpt:") != 0)
        return 501;

    if (check_user(0, rcpt, rcpt, NULL))
        return 501;

    if((rlen = BIO_gets(buf_io, header3, sizeof header - 1)) < 0)
        return 400;

    len_prompt = strtok(header3, inline_sep);
    len = strtok(NULL, inline_sep); 
    stray_chars = strtok(NULL, inline_sep);

    if (!len_prompt || !len || stray_chars)
        return 501;    

    //TODO make it check uper and lowercase......!!!
    strlower(len_prompt);
    if (strcmp(len_prompt, "content-length:") != 0)
        return 501;

    if (!(l = atoi(len)))
        return 501;
    if (l <= 0)
        return 400;

    if((rlen = BIO_gets(buf_io, header4, sizeof header - 1)) < 0)
        return 400;

    if (strcmp(header4, "\r\n") != 0)
        return 501;


    char newpath[4069];
    snprintf(newpath, 4065, "message-sys/pub/mail/%s", rcpt);
    DIR * dr = opendir(newpath);
    struct dirent *de;

    /* Get tail in current directory */
    int count = -1;

    while ((de = readdir(dr)) != NULL)
        count++;

    closedir(dr);
    char newfile[7];

    sprintf(newfile, "/%05d", count);
    strncat(newpath, newfile, 7);
    FILE *saveme = fopen(newpath, "wb");
    if (saveme == NULL) {
        return 400;
    }

    char sender[strlen(user) + 2];
    strcpy(sender, user);
    strcat(sender, "\n");
    sender[strlen(user) + 2] = '\0';

    fwrite(sender, 1, strlen(sender), saveme);
    char lineptr[4096];
    int remaining = l;
    int limit; int r;

    while (remaining > 0) {
        limit = remaining > sizeof(lineptr) ? sizeof(lineptr) : remaining;
        //r = SSL_read(ssl, lineptr, l);
        /* if new line is encountered, break but include it inthe buffer */
        r = BIO_read(buf_io, lineptr, limit);
        if (r < 0) {
            return 400;
        }
        else if (r == 0) {
            return 400;
        }
        else {
            remaining -= r;
            fwrite(lineptr, 1, r, saveme);
        }
    }

    //r = snprintf(lineptr, 2, "\n");
    //fwrite(lineptr, 1, 1, saveme);
    fclose(saveme);
    send_status(ssl, sock, 200);
    SSL_write(ssl, "\r\n", 2);
    return 0;
}

int recv_msg(BIO *buf_io, SSL *ssl, int sock)
{
    int rlen, n;

    char header[1008], buf[4096];
    char header4[1008];

    char *user_prompt, *stray_chars;
    char *user;

    char *inline_sep = " \r\n";

    if ((rlen = BIO_gets(buf_io, header, sizeof header - 1)) < 0)
        return 400;

    user_prompt = strtok(header, inline_sep);
    user = strtok(NULL, inline_sep); 
    stray_chars = strtok(NULL, inline_sep);

    if (!user_prompt || !user || stray_chars)
        return 501;    

    if (strcmp(user_prompt, "User:") != 0)
        return 501;

    if (check_user(0, user, user, NULL))
        return 501;
    if((rlen = BIO_gets(buf_io, header4, sizeof header - 1)) < 0)
        return 400;
    if (strcmp(header4, "\r\n") != 0)
        return 501;


    char newpath[4069];
    snprintf(newpath, 4065, "message-sys/pub/mail/%s", user);

    DIR * dr = opendir(newpath);
    struct dirent *de;

    /* Get tail in current directory */
    int count = -1;


    while ((de = readdir(dr)) != NULL)
        count++;

    count--;
    closedir(dr);
    if (count < 1)
        return 400;

    char newfile[7];

    sprintf(newfile, "/%05d", count);
    strncat(newpath, newfile, 7);
    FILE *saveme = fopen(newpath, "rb");
    if (saveme == NULL) {
        return 400;
    }
    /* read sender and add that as a header... */
    unsigned long file_size;
    fseek(saveme, 0L, SEEK_END);
    file_size = ftell(saveme);
    fseek(saveme, 0L, SEEK_SET);

    char sender[4096];

    fgets(sender, sizeof(sender), saveme); 

    /* get the file size to include a content header thing. */
    /* Data communication - sending encrypted message from out to ssl connection*/
    char obuf[4096];
    memset(obuf, 0, sizeof(obuf));
    send_status(ssl, sock, 200);
    n = snprintf(obuf, 512, "From: %sContent-Length: %lu\r\n\r\n",
            sender, file_size);

    SSL_write(ssl, obuf, n);
    while ((n = fread(buf, 1, sizeof(obuf), saveme)) > 0) {
        SSL_write(ssl, buf, n); 
    }   

    fclose(saveme);

    if (remove(newpath) != 0) {
        perror("Deleting file");
    }

    SSL_write(ssl, obuf, n);
    return 0;
}

int get_inter_cert(BIO *buf_io, SSL *ssl, int sock)
{
    int rlen, n;

    char header[1008], buf[4096];
    char header4[1008];

    char *user_prompt, *stray_chars;
    char *user;

    FILE *fd;
    char *inline_sep = " \r\n";

    if ((rlen = BIO_gets(buf_io, header, sizeof header - 1)) < 0)
        return 400;

    user_prompt = strtok(header, inline_sep);
    user = strtok(NULL, inline_sep); 
    stray_chars = strtok(NULL, inline_sep);

    if (!user_prompt || !user || stray_chars)
        return 501;    

    if (strcmp(user_prompt, "User:") != 0)
        return 501;

    if ((rlen = BIO_gets(buf_io, header4, sizeof header - 1)) < 0)
        return 400;

    if (strcmp(header4, "\r\n") != 0)
        return 501;

    if (check_user(0, user, user, NULL))
        return 501;

    /* Read in and send the certificate */
    //snprintf(namebuf, 999, "message-sys/priv/%s/cert/%s.cert.pem", user, user);
    fd = fopen("ca/intermediate/certs/intermediate.cert.pem", "rb");
    if (fd == NULL) {
        return 400;
    }

    send_status(ssl, sock, 200);
    char content[4096];
    fseek(fd, 0L, SEEK_END);
    unsigned long file_size = ftell(fd);
    fseek(fd, 0L, SEEK_SET);
    n = snprintf(content, 4000, "Content-Length: %ld\r\n\r\n", file_size);
    SSL_write(ssl, content, n);
    while ((n = fread(buf, 1, sizeof(buf), fd)) > 0) {
        SSL_write(ssl, buf, n);
    }

    fclose(fd);
    return 0;
}

int get_root_cert(BIO *buf_io, SSL *ssl, int sock)
{
    int rlen, n;

    char header[1008], buf[4096];
    char header4[1008];

    char *user_prompt, *stray_chars;
    char *user;

    FILE *fd;
    char *inline_sep = " \r\n";

    if ((rlen = BIO_gets(buf_io, header, sizeof header - 1)) < 0)
        return 400;

    user_prompt = strtok(header, inline_sep);
    user = strtok(NULL, inline_sep); 
    stray_chars = strtok(NULL, inline_sep);

    if (!user_prompt || !user || stray_chars)
        return 501;    

    if (strcmp(user_prompt, "User:") != 0)
        return 501;

    if ((rlen = BIO_gets(buf_io, header4, sizeof header - 1)) < 0)
        return 400;

    if (strcmp(header4, "\r\n") != 0)
        return 501;

    if (check_user(0, user, user, NULL))
        return 501;

    /* Read in and send the certificate */
    //snprintf(namebuf, 999, "message-sys/priv/%s/cert/%s.cert.pem", user, user);
    fd = fopen("ca/certs/ca.cert.pem", "rb");
    if (fd == NULL) {
        return 400;
    }

    send_status(ssl, sock, 200);
    char content[4096];
    fseek(fd, 0L, SEEK_END);
    unsigned long file_size = ftell(fd);
    fseek(fd, 0L, SEEK_SET);
    n = snprintf(content, 4000, "Content-Length: %ld\r\n\r\n", file_size);
    SSL_write(ssl, content, n);
    while ((n = fread(buf, 1, sizeof(buf), fd)) > 0) {
        SSL_write(ssl, buf, n);
    }

    fclose(fd);
    return 0;
}

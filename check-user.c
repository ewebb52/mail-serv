/* 
 * Check if user exists in our system
 *
 * @user: name of message box directory
 */

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <limits.h>
#include <regex.h>
#include <sys/stat.h>
#include <dirent.h>
#include <ctype.h>

char *prepath = "message-sys/pub/mail/";

char *strupper(char *str)
{
    int i = 0;

    while (i < strlen(str)) {
        str[i] = toupper(str[i]);
        i++;
    }

    return NULL;
}

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

int main(int argc, char **argv) 
{
    if (argc != 2)
        exit(EINVAL);

    int r;
    struct stat statbuf;
    char *name;

    name = argv[1];
    r = strlen(name);
    char path[r + strlen(prepath) + 1 + 6];

    strncpy(path, prepath, strlen(prepath) + 1);
    strncat(path, name, strlen(name) + 1);

    if (strlower(path))
        exit(EINVAL);

    stat(path, &statbuf);

    if (stat(path, &statbuf) == -1)
        exit(EINVAL);

    if (!S_ISDIR(statbuf.st_mode))
        exit(EINVAL);

    fprintf(stderr, "Valid user: %s\n", path);
    exit(0);
}

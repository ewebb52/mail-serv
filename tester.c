/*
 * tester: runs specific test case specified by command line arguments
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

#define GETCERT "getcert"
#define CHANGEPW "changepw"
#define SENDMSG "sendmsg"
#define RECVMSG "recvmsg"

void print_usage(void)
{
    fprintf(stderr, "usage: tester <program-to-test> <username> <password> <server-ip>\n");
}

int fork_exec(char* to_execv, char** args) {
	int status, pid = fork();

	if (pid < 0) {
		fprintf(stderr, "fork failed :(");
		return 1;
	}
    if (!pid) {
        execv(to_execv, args);
        perror("Execl failed");
        return 1;
    } else {
        pid = wait(&status);
        if (WEXITSTATUS(status) == EINVAL)
            return -1;
		return 0;
	}
}

int main(int argc, char **argv)
{
	char *test_program, *to_exec; 
//*user, *password, *server_ip;
//	int pid, status;
//	char **args;

	test_program = argv[1];
//    user = argv[2];
//    password = argv[3];
//    server_ip = argv[4];

    if (argc != 5) {
        print_usage();
        exit(-1);
    }

	to_exec = malloc(strlen(test_program) + 3);	
	snprintf(to_exec, 3, "./");
	snprintf(to_exec + 2, strlen(test_program), "%s", test_program);
	to_exec[strlen(test_program) + 2] = '\0';

/*
        execl(to_execlt, to_execl, user, password, server_ip, NULL);
	args = malloc(sizeof(*argv) * (argc-2))
	for int i = 0; i < argc - 2; i++ {
		args[i] = malloc(strlen(argv[i + 2]) + 1);
		strcpy(args[i], argv[i + 2]);
	}	
*/

	int ret = fork_exec(test_program, argv + 1);
	free(to_exec);
	if (!ret) {
		exit(1);
	}

/*
	switch (test_program) {
		case GETCERT:
			break;
		case CHANGEPW:
			break;

		case SENDMSG:
			break;

		case RECVMSG:
			break;
	}
*/
	return ret;
}

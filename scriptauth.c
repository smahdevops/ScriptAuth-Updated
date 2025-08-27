#include "../../structures.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <netdb.h>

static int already_loaded = 0;
static struct auth scriptauth;
static unsigned char *service = NULL;
static struct pluginlink *pl;

/* small helper: run the script as a child and return its exit code */
static int run_script(const char *path, char *const argv[]) {
    pid_t pid = fork();
    if (pid < 0) {
        return 1; /* fork failed -> deny */
    }
    if (pid == 0) {
        /* child */
        execv(path, argv);
        _exit(127); /* exec failed */
    }
    int status = 0;
    if (waitpid(pid, &status, 0) < 0) {
        return 1;
    }
    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }
    return 1; /* treat signals/other as failure */
}

/**
 * Implements scriptauthFunc()
 * argv passed to script:
 *   argv[0] = script path
 *   argv[1] = username (or "-")
 *   argv[2] = password (or "-")
 *   argv[3] = local-bind host (numeric)
 *   argv[4] = local-bind port (numeric)
 *   argv[5] = client source IP (numeric, v4/v6)
 *   argv[6] = NULL
 */
static int scriptauthFunc(struct clientparam *param) {
    int rc = 1; /* default deny */

    /* --- local bind address/port (what 3proxy accepted on) --- */
    char hoststr[NI_MAXHOST] = "0.0.0.0";
    char portstr[NI_MAXSERV] = "0";
    {
        struct sockaddr_storage lss;
        socklen_t lss_len = sizeof(lss);
        if (getsockname(param->clisock, (struct sockaddr *)&lss, &lss_len) == 0) {
            (void)getnameinfo((struct sockaddr *)&lss, lss_len,
                              hoststr, sizeof(hoststr),
                              portstr, sizeof(portstr),
                              NI_NUMERICHOST | NI_NUMERICSERV);
        }
    }

    /* --- client source IP (remote peer) --- */
    char client_ip[INET6_ADDRSTRLEN] = "0.0.0.0";
    {
        struct sockaddr_storage rss;
        socklen_t rss_len = sizeof(rss);
        if (getpeername(param->clisock, (struct sockaddr *)&rss, &rss_len) == 0) {
            if (rss.ss_family == AF_INET) {
                inet_ntop(AF_INET, &((struct sockaddr_in *)&rss)->sin_addr,
                          client_ip, sizeof(client_ip));
            }
#ifdef AF_INET6
            else if (rss.ss_family == AF_INET6) {
                inet_ntop(AF_INET6, &((struct sockaddr_in6 *)&rss)->sin6_addr,
                          client_ip, sizeof(client_ip));
            }
#endif
        } else {
            /* fallback to the address inside clientparam if available (IPv4) */
#ifdef SAADDR
            snprintf(client_ip, sizeof client_ip, "%u.%u.%u.%u",
                     (unsigned)(((unsigned char *)(SAADDR(&param->sincr)))[0]),
                     (unsigned)(((unsigned char *)(SAADDR(&param->sincr)))[1]),
                     (unsigned)(((unsigned char *)(SAADDR(&param->sincr)))[2]),
                     (unsigned)(((unsigned char *)(SAADDR(&param->sincr)))[3]));
#endif
        }
    }

    /* --- username/password (never pass NULL to execv) --- */
    char *username = (param->username && *param->username) ? (char *)param->username : "-";
    char *password = (param->password && *param->password) ? (char *)param->password : "-";

    /* --- build argv vector (NO shell) --- */
    char *argv[7];
    argv[0] = (char *)service;
    argv[1] = username;
    argv[2] = password;
    argv[3] = hoststr;
    argv[4] = portstr;
    argv[5] = client_ip;
    argv[6] = NULL;

    /* run the script; exit code 0 => allow, non-zero => deny */
    rc = run_script((const char *)service, argv);

    return rc;
}

#ifdef WATCOM
#pragma aux start "*" parm caller [ ] value struct float struct routine [eax] modify [eax ecx edx]
#undef PLUGINCALL
#define PLUGINCALL
#endif

/**
 * Init/start plugin.
 */
PLUGINAPI int PLUGINCALL start(struct pluginlink *pluginlink, int argc, unsigned char **argv) {
    if (argc < 2) return 1;

    pl = pluginlink;

    if (service) free(service);
    service = (unsigned char *)strdup((char *)argv[1]);

    if (already_loaded) { return 0; }
    already_loaded = 1;

    scriptauth.authenticate = scriptauthFunc;
    scriptauth.authorize    = pluginlink->checkACL;
    scriptauth.desc         = "script";
    scriptauth.next         = pluginlink->authfuncs->next;
    pluginlink->authfuncs->next = &scriptauth;

    return 0;
}

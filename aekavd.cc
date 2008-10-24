//
// Example of KAV Daemon
//
// Main file
//
//


#include <signal.h>
#include <syslog.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <argp.h>
#include <iostream>
#include <sstream>
#include <fstream>
#include <stdexcept>
#include <string>
#include "options.h"
#include "kav.h"
#include "pidfile.h"
#include "error.h"
#include "session.h"


#define AEKAVD_DEF_CONFIGFILE "/etc/aekavd.conf"

#define VERSION_STR      "1.0.0"


const char *argp_program_version     = "aekavd " VERSION_STR;
const char *argp_program_bug_address = "<bugs@example.com>";

namespace AEKAVD {

    enum Return_codes {
        AEKAVD_RC_OK   = 0,
        AEKAVD_RC_EXC  = 5
    };


    static int ctl_pipe[2];


    static int  main(int, char *[]);
    static void daemon();
    static void open_control_pipe();
    static void install_sig_hadlers();
    static void log_and_save_kav_info(const std::string& fn);
    static int  open_listen_socket(uint32_t, uint16_t);
    static int  incoming_connection(int);
    static void sig_stop_handler(int);
    static void sig_child_handler(int);


    // command line parsing stuff
    static error_t parse_opt(int key, char *arg, struct argp_state *state);
    static struct argp_option options[] = {
        {"config", 'c', "FILE", 0, "Use file FILE as config file. Default " AEKAVD_DEF_CONFIGFILE },
        { 0 }
    };
    struct Arguments {
        const char *config_file;
    };
    const char *argp_program_version = "aekavd " VERSION_STR;
    const char *argp_program_bug_address = "<bugsd@example.com>";
    static char doc[] = "Example of AltEll KAV Antivirus Daemon -- scans files for viruses on demand";
    static struct argp argp = { options, parse_opt, 0, doc };
}


int main(int argc, char *argv[])
{
    return AEKAVD::main(argc, argv);
}

int AEKAVD::main(int argc, char *argv[])
{
    int rc = AEKAVD_RC_OK;

    try {
        Arguments arguments;
        arguments.config_file = AEKAVD_DEF_CONFIGFILE;

        argp_parse(&argp, argc, argv, 0, 0, &arguments);
        Options options(arguments.config_file);

        // init
        openlog(program_invocation_short_name, options.syslog_options(), options.syslog_facility());
        if (options.is_daemon()) daemon();
        syslog(LOG_INFO, "started; version: %s; config file: %s", VERSION_STR, arguments.config_file);
        Pid_file pidfile(options.pid_file());
        open_control_pipe();
        install_sig_hadlers();
        kav_open(options.kav_key_path(), options.kav_base_path());
        log_and_save_kav_info(options.kav_info_file());
        int sock = open_listen_socket(options.listen_addr(), options.listen_port());

        // listen for incoming connections and control events
        bool done = false;
        bool parent = true;
        while (!done) {
            int connsock = incoming_connection(sock);
            if (connsock == -1)
                done = true;
            else {
                switch (fork()) {
                case 0:
                    // child
                    done = true;
                    parent = false;
                    close(sock);
                    sock = connsock;
                    handle_session(sock, options.log_found_viruses());
                    break;
                case -1:
                    syslog(LOG_ERR, "fork failed: %s", strerror(errno));
                    break;
                default:
                    // parent
                    close(connsock);
                    break;
                }
            }
        }

        // cleanup and exit
        close(sock);
        if (parent) kav_close();
    }
    catch (std::exception& exc) {
        syslog(LOG_ERR, "fatal exception: %s", exc.what());
        rc = AEKAVD_RC_EXC;
    }

    syslog(LOG_INFO, "finished with rc: %d", rc);
    return rc;
}

error_t AEKAVD::parse_opt(int key, char *arg, struct argp_state *state)
{
    struct Arguments *arguments = reinterpret_cast<Arguments *>(state->input);

    switch (key) {
    case 'c':
        arguments->config_file = arg;
        break;
    case ARGP_KEY_ARG:
        // too many arguments
        argp_usage(state);
        break;
    case ARGP_KEY_END:
        if (state->arg_num != 0)
            argp_usage(state);
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

void AEKAVD::daemon()
{
    errno = 0;
    if (::daemon(0, 0) != 0)
        syscall_error("daemon", errno);
}

void AEKAVD::open_control_pipe()
{
    if (pipe(ctl_pipe) != 0)
        syscall_error("pipe", errno);
}

void AEKAVD::install_sig_hadlers()
{
    sigset_t blockmask;
    sigemptyset(&blockmask);
    sigaddset(&blockmask, SIGTERM);
    sigaddset(&blockmask, SIGINT);

    struct sigaction stopaction;
    stopaction.sa_handler = sig_stop_handler;
    stopaction.sa_mask    = blockmask;
    stopaction.sa_flags   = SA_RESTART;

    if (sigaction(SIGTERM, &stopaction, 0) != 0)
        error<std::runtime_error>("sigaction failed for signal: SIGTERM; errro", strerror(errno));
    if (sigaction(SIGINT, &stopaction, 0) != 0)
        error<std::runtime_error>("sigaction failed for signal: SIGINT; errro", strerror(errno));

    sigemptyset(&blockmask);
    sigaddset(&blockmask, SIGCHLD);

    struct sigaction childaction;
    childaction.sa_handler = sig_child_handler;
    childaction.sa_mask    = blockmask;
    childaction.sa_flags   = SA_RESTART;

    if (sigaction(SIGCHLD, &childaction, 0) != 0)
        error<std::runtime_error>("sigaction failed for signal: SIGCHLD; errro", strerror(errno));
}

void AEKAVD::log_and_save_kav_info(const std::string& fn)
{
    Kav_info kavinfo;
    kav_set_info(kavinfo);
    syslog(LOG_INFO, "KAV SDK version: %s", kavinfo.sdk_version.c_str());
    syslog(LOG_INFO, "KAV database info: number of records: %s; virus db release date: %s", kavinfo.num_records.c_str(), kavinfo.db_release_date.c_str());
    syslog(LOG_INFO, "KAV licence info: used key file: %s; expiration date: %s", kavinfo.used_key_file.c_str(), kavinfo.expire_date.c_str());

    std::ofstream os(fn.c_str());
    if (!os) {
        syslog(LOG_ERR, "can't open kav info file: %s; error: %s", fn.c_str(), strerror(errno));
        return;
    }

    os << kavinfo.sdk_version     << std::endl
       << kavinfo.num_records     << std::endl
       << kavinfo.db_release_date << std::endl
       << kavinfo.used_key_file   << std::endl
       << kavinfo.expire_date     << std::endl;
}

int AEKAVD::open_listen_socket(uint32_t naddr, uint16_t port)
{
    int sock = socket(PF_INET, SOCK_STREAM, 0);
    if (sock < 0)
        syscall_error("socket", errno);

    int val = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val)) != 0)
        syscall_error("setsockopt", errno);

    struct sockaddr_in name;
    name.sin_family = AF_INET;
    name.sin_port = htons(port);
    name.sin_addr.s_addr = naddr;
    if (bind(sock, (struct sockaddr *) &name, sizeof(name)) != 0) {
        std::ostringstream s;
        s << "failed to bind socket: " << inet_ntoa(name.sin_addr) << ":" << port << ": " << strerror(errno);
        throw std::runtime_error(s.str());
    }

    if (listen(sock, 1) < 0)
        syscall_error("listen", errno);

    return sock;
}

int AEKAVD::incoming_connection(int lsock)
{
    fd_set readfdset;
    FD_ZERO(&readfdset);
    FD_SET(lsock, &readfdset);
    FD_SET(ctl_pipe[0], &readfdset);

    int connsock = -1;
    while (true) {
        int rc = select(FD_SETSIZE, &readfdset, NULL, NULL, NULL);
        if (rc < 0) {
            if (errno == EINTR)
                syslog(LOG_DEBUG, "select was interrutped with signal; resuming");
            else
                syscall_error("select", errno);
        } else if (rc > 0) {
            if (FD_ISSET(ctl_pipe[0], &readfdset)) {
                connsock = -1;
                syslog(LOG_DEBUG, "got control event; exiting");
                break;
            } else if (FD_ISSET(lsock, &readfdset)) {
                struct sockaddr clientaddr;
                socklen_t len;
                connsock = accept(lsock, &clientaddr, &len);
                // todo: output client's address
                syslog(LOG_INFO, "got incoming connection");
                break;
            }
        }
    }

    return connsock;
}

void AEKAVD::sig_stop_handler(int signum)
{
    char buf[1] = { signum };
    write(ctl_pipe[1], buf, 1);
}

void AEKAVD::sig_child_handler(int)
{
    int status;
    int serrno = errno;

    while (1) {
        if (waitpid (WAIT_ANY, &status, WNOHANG) <= 0)
            break;
    }

    errno = serrno;
}

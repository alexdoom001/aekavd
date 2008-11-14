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
#include <sys/un.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <argp.h>
#include <iostream>
#include <sstream>
#include <fstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <pthread.h>
#include <time.h>
#include "options.h"
#include "kav.h"
#include "pidfile.h"
#include "error.h"
#include "session.h"


#define AEKAVD_DEF_CONFIGFILE "/etc/aekavd.conf"

#define VERSION_STR      "1.0.0"


const char *argp_program_version     = "aekavd " VERSION_STR;
const char *argp_program_bug_address = "<bugs@example.com>";

typedef void (*PosixTimerCallback)(union sigval);
typedef void (*TimerCallback)();
#define TIMER_INVALID (timer_t)-1;

namespace AEKAVD {

    enum Return_codes {
        AEKAVD_RC_OK   = 0,
        AEKAVD_RC_EXC  = 5
    };


    int ctl_pipe[2];

    static int  main(int, char *[]);
    static void daemon();
    static void open_control_pipe();
    static void install_sig_hadlers();
    static void log_and_save_kav_info(const std::string& fn);
    static int  open_listen_tcp_socket(uint32_t, uint16_t);
    static int  open_listen_unix_socket(const std::string&);
    static int  incoming_connection(int, int, bool *);

    static void try_reload_database();
    static void reload_database();
    static timer_t create_timer(TimerCallback cb);
    static void destroy_timer(timer_t timer);
    static int set_timeout(timer_t timer, int timeout);

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

    bool reload_database_processing;
    bool reload_database_timer_set;
    timer_t reload_database_timer;
    pthread_mutex_t reload_database_mutex;
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
        syslog(LOG_NOTICE, "started; version: %s; config file: %s", VERSION_STR, arguments.config_file);
        Pid_file pidfile(options.pid_file());
        open_control_pipe();
        install_sig_hadlers();
        kav_open(options.kav_key_path(), options.kav_base_path());

        if(!options.kav_info_file().empty())
            log_and_save_kav_info(options.kav_info_file());

        int tcp_sock = -1, unix_sock;
        if(options.listen_addr() != 0 && options.listen_port() != 0)
            tcp_sock = open_listen_tcp_socket(options.listen_addr(), options.listen_port());
        unix_sock = open_listen_unix_socket(options.listen_socket());
        int connsock = -1;

        // listen for incoming connections and control events
        bool done = false;
        bool parent = true;
        bool reload_database_sig = false;
        reload_database_processing = false;
        reload_database_timer_set = false;

        reload_database_timer = create_timer(try_reload_database);
        pthread_mutex_init(&reload_database_mutex, NULL);

        while (!done) {
            connsock = incoming_connection(tcp_sock, unix_sock, &reload_database_sig);
            if (connsock == -1 && !reload_database_sig)
                done = true;
            else {
                if (reload_database_sig) {
                    reload_database();
                    continue;
                }
                switch (fork()) {
                case 0:
                    // child
                    done = true;
                    parent = false;
                    if(tcp_sock != -1)
                        close(tcp_sock);
                    close(unix_sock);
					handle_session(connsock, options.stream_limit());
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
        if (parent) {
            pthread_mutex_destroy(&reload_database_mutex);
            destroy_timer(reload_database_timer);
            if(tcp_sock != -1)
                close(tcp_sock);
            close(unix_sock);
            unlink(options.listen_socket().c_str());
            kav_close();
            pidfile.Pid_file_remove();
            syslog(LOG_INFO, "finished with rc: %d", rc);
            return rc;
        } else
            return close(connsock);
    }
    catch (std::exception& exc) {
        syslog(LOG_ERR, "fatal exception: %s", exc.what());
        rc = AEKAVD_RC_EXC;
    }
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
    sigaddset(&blockmask, SIGHUP);

    struct sigaction stopaction;
    memset(&stopaction, 0 ,sizeof(stopaction));
    stopaction.sa_handler = sig_stop_handler;
    stopaction.sa_mask    = blockmask;
    stopaction.sa_flags   = SA_RESTART;

    if (sigaction(SIGINT, &stopaction, 0) != 0)
            error<std::runtime_error>("sigaction failed for signal: SIGINT; errro", strerror(errno));
    if (sigaction(SIGTERM, &stopaction, 0) != 0)
        error<std::runtime_error>("sigaction failed for signal: SIGTERM; errro", strerror(errno));
    if (sigaction(SIGHUP, &stopaction, 0) != 0)
        error<std::runtime_error>("sigaction failed for signal: SIGHUP; errro", strerror(errno));

    sigemptyset(&blockmask);
    sigaddset(&blockmask, SIGCHLD);

    struct sigaction childaction;
    memset(&childaction, 0 ,sizeof(childaction));
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

int AEKAVD::open_listen_tcp_socket(uint32_t naddr, uint16_t port)
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

int AEKAVD::open_listen_unix_socket(const std::string& path)
{
    int sock = socket(PF_UNIX, SOCK_STREAM, 0);
    if (sock < 0)
        syscall_error("socket", errno);

    sockaddr_un name;
    name.sun_family = AF_UNIX;
    strcpy(name.sun_path, path.c_str());
    if (bind(sock, (struct sockaddr *) &name, sizeof(name)) != 0) {
        std::ostringstream s;
        s << "failed to bind socket: " << path << ": " << strerror(errno);
        throw std::runtime_error(s.str());
    }

    if(chmod(name.sun_path, 0777)) {
        std::ostringstream s;
        s << "failed to chmod socket: " << path << ": " << strerror(errno);
		throw std::runtime_error(s.str());
    }

    if (listen(sock, 1) < 0)
        syscall_error("listen", errno);

    return sock;
}

int AEKAVD::incoming_connection(int tcp_sock, int unix_sock, bool *reload_databases)
{
    fd_set readfdset;
    FD_ZERO(&readfdset);
    if(tcp_sock != -1)
        FD_SET(tcp_sock, &readfdset);
    FD_SET(unix_sock, &readfdset);
    FD_SET(ctl_pipe[0], &readfdset);

    char buf[1];
    int connsock = -1;
    *reload_databases = false;
    while (true) {
        int rc = select(FD_SETSIZE, &readfdset, NULL, NULL, NULL);
        if (rc < 0) {
            if (errno == EINTR)
                syslog(LOG_DEBUG, "select was interrutped with signal; resuming");
            else
                syscall_error("select", errno);
        } else if (rc > 0) {
            if (FD_ISSET(ctl_pipe[0], &readfdset)) {
                if(read(ctl_pipe[0], buf, 1) == 1)
                    if(buf[0] == SIGHUP)
                        *reload_databases = true;
                connsock = -1;
                syslog(LOG_DEBUG, "got control event; exiting");
                break;
            } else if (tcp_sock != -1 && FD_ISSET(tcp_sock, &readfdset)) {
                struct sockaddr clientaddr;
                socklen_t len = NULL;
                if ((connsock = accept(tcp_sock, &clientaddr, &len)) == -1)
                    syslog(LOG_NOTICE, "accept error: %s", strerror(errno));
                // todo: output client's address
                syslog(LOG_INFO, "got incoming tcp-socket connection");
                break;
            } else if (FD_ISSET(unix_sock, &readfdset)) {
                struct sockaddr clientaddr;
                socklen_t len = NULL;
                if ((connsock = accept(unix_sock, &clientaddr, &len)) == -1)
                    syslog(LOG_NOTICE, "accept error: %s", strerror(errno));
                syslog(LOG_INFO, "got incoming unix-socket connection");
                break;
            }
        }
    }

    return connsock;
}

static void AEKAVD::try_reload_database()
{
	pthread_mutex_lock(&reload_database_mutex);
	if(reload_database_processing) {
		set_timeout(reload_database_timer, 60);
		reload_database_timer_set = true;
		pthread_mutex_unlock(&reload_database_mutex);
	}
	else {
		reload_database_timer_set = false;
		reload_database_processing = true;
		pthread_mutex_unlock(&reload_database_mutex);
		kav_reload_database(NULL);
	}
}

static void AEKAVD::reload_database()
{
	pthread_t thread;
	pthread_mutex_lock(&reload_database_mutex);
	if(reload_database_processing) {
		if(!reload_database_timer_set) {
			set_timeout(reload_database_timer, 60);
			reload_database_timer_set = true;
		}
	}
	else {
		reload_database_processing = true;
		pthread_create(&thread, NULL, kav_reload_database, NULL);
	}
	pthread_mutex_unlock(&reload_database_mutex);
}

static timer_t AEKAVD::create_timer(TimerCallback cb)
{
    struct sigevent evp;
    timer_t tmr;

    evp.sigev_notify = SIGEV_THREAD;
    evp.sigev_notify_function = (PosixTimerCallback)cb;
    evp.sigev_notify_attributes = NULL;

    int r = timer_create(CLOCK_REALTIME, &evp, &tmr);
    if (r == -1)
        tmr = TIMER_INVALID;

    return tmr;
}

static void AEKAVD::destroy_timer(timer_t timer)
{
    timer_delete(timer);
}

static int AEKAVD::set_timeout(timer_t timer, int timeout)
{
    struct itimerspec ts;
    memset(&ts, 0, sizeof(ts));
    ts.it_value.tv_sec = (time_t) timeout;
    return timer_settime(timer, 0, &ts, NULL);
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

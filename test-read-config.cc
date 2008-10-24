#include <arpa/inet.h>
#include <syslog.h>
#include <iostream>
#include "options.h"

using AEKAVD::Options;

std::ostream& operator<<(std::ostream&, const Options&);

int main(int argc, char *argv[])
{
    // todo: check args

    try {
        std::string fn(argv[1]);
        Options opts(fn);
        std::cout << opts << std::endl;
    }
    catch (std::exception& exc) {
        std::cout << "error: " << exc.what() << std::endl;
        return 1;
    }

    return 0;
}

std::ostream& operator<<(std::ostream& os, const Options& opts)
{
    struct in_addr addr;
    addr.s_addr = opts.listen_addr();

    os << "is daemon         = " << (opts.is_daemon() ? "true" : "false")                     << std::endl
       << "syslog-perror     = " << ((opts.syslog_options() & LOG_PERROR) ? "true" : "false") << std::endl
       << "syslog-facility   = " << opts.syslog_facility()                                    << std::endl
       << "pid-file          = " << opts.pid_file()                                           << std::endl
       << "kav-key-path      = " << opts.kav_key_path()                                       << std::endl
       << "kav-base-path     = " << opts.kav_base_path()                                      << std::endl
       << "listen-addr       = " << inet_ntoa(addr)                                           << std::endl
       << "listen-port       = " << opts.listen_port()                                        << std::endl
       << "kav-info-file     = " << opts.kav_info_file()                                      << std::endl
       << "log-found-viruses = " << (opts.log_found_viruses() ? "true" : "false")             << std::endl;

    return os;
}

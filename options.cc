//
// Example of KAV Daemon
//
// Options and config file parsing
// Implementaion
//
//


#include <stdint.h>
#include <syslog.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdexcept>
#include <fstream>
#include <sstream>
#include <linux/un.h>
#include "error.h"
#include "options.h"

#define STREAM_LIMIT 1024 * 1024 * 128

namespace AEKAVD {

    enum Token_type {
        TOK_KEYWORD = 0,
        TOK_EQUAL,
        TOK_STRING,
        TOK_EOF
    };

    enum Keyword_code {
        KW_UNKNOWN     = -1,
        KW_FIRST       = 0,
        KW_LISTEN_ADDR = KW_FIRST,
        KW_LISTEN_PORT,
        KW_UNIX_SOCKET,
        KW_STREAM_LIMIT,
        KW_KAV_LICENCE_PATH, 
        KW_KAV_BASES_PATH,
        KW_DAEMON_MODE,
        KW_PID_FILE,
        KW_SYSLOG_PERROR,
        KW_SYSLOG_FACILITY,
        KW_KAV_INFO_FILE,
        KW_LOG_FOUND_VIRUSES,
        KW_NUM
    };

    struct Token {
        int type;
        int int_val;
        std::string str_val;

        Token();
        Token(int, int, const std::string&);
    };

    struct Syslog_facility_descr {
        const char *str;
        int val;
    };


    static void  parse_config_file(const std::string&, Options*);
    static Token string_to_token(const std::string&);
    static void  set_option_value(int, const std::string&, Options*);
    static void  set_listen_addr(const std::string&, Options*);
    static void  set_listen_port(const std::string&, Options*);
    static void  set_unix_socket(const std::string&, Options*);
    static void  set_stream_limit(const std::string&, Options*);
    static void  set_daemon_mode(const std::string&, Options*);
    static void  set_log_found_viruses(const std::string&, Options*);
    static void  set_syslog_perror(const std::string&, Options*);
    static void  set_syslog_facility(const std::string&, Options*);
    static void  syntax_error(const std::string& expected, const std::string& got);


    static std::string keyword_str[KW_NUM] = {
        std::string("listen-addr"),             // KW_LISTEN_ADDR
        std::string("listen-port"),             // KW_LISTEN_PORT,
        std::string("listen-unix-socket"),      // KW_UNIX_SOCKET
        std::string("stream-limit"),            // KW_STREAM_LIMIT
        std::string("kav-licence-path"),        // KW_KAV_LICENCE_PATH, 
        std::string("kav-bases-path"),          // KW_KAV_BASES_PATH,   
        std::string("daemon-mode"),             // KW_DAEMON_MODE,      
        std::string("pid-file"),                // KW_PID_FILE,         
        std::string("syslog-perror"),           // KW_SYSLOG_PERROR,    
        std::string("syslog-facility"),          // KW_SYSLOG_FACILITY,
        std::string("kav-info-file"),           // KW_KAV_INFO_FILE
        std::string("log-found-viruses")        // KW_LOG_FOUND_VIRUSES
    };

    static Syslog_facility_descr syslog_facility_tab[] = {
        { "USER",     LOG_USER     },
        { "MAIL",     LOG_MAIL     },
        { "DAEMON",   LOG_DAEMON   },
        { "AUTH",     LOG_AUTH     },
        { "SYSLOG",   LOG_SYSLOG   },
        { "LPR",      LOG_LPR      },
        { "NEWS",     LOG_NEWS     },
        { "UUCP",     LOG_UUCP     },
        { "CRON",     LOG_CRON     },
        { "AUTHPRIV", LOG_AUTHPRIV },
        { "FTP",      LOG_FTP      },
        { "LOCAL0",   LOG_LOCAL0   },
        { "LOCAL1",   LOG_LOCAL1   },
        { "LOCAL2",   LOG_LOCAL2   },
        { "LOCAL3",   LOG_LOCAL3   },
        { "LOCAL4",   LOG_LOCAL4   },
        { "LOCAL5",   LOG_LOCAL5   },
        { "LOCAL6",   LOG_LOCAL6   },
        { "LOCAL7",   LOG_LOCAL7   }
    };

    static const int SLF_NUM = sizeof(syslog_facility_tab) / sizeof(Syslog_facility_descr);


    //
    // inlines
    //
    inline Token::Token()                                   : type(-1), int_val(0)             {}
    inline Token::Token(int t, int i, const std::string& s) : type(t),  int_val(i), str_val(s) {}
}


AEKAVD::Options::Options(const std::string& fn)
    : naddr(0),
      port(0),
      unix_socket("/var/run/aekavd.socket"),
      streamlimit(1024 * 1024 * 64),
      isdaemon(true),
      kavkeypath("/var/lib/kav/licences"),
      kavbasepath("/var/lib/kav/bases"),
      pidfile("/var/run/aekavd.pid"),
      syslogopts(LOG_PID|LOG_NDELAY),
      syslogfacility(LOG_DAEMON),
      kavinfofile(""),
      logfoundviruses(false)
{
    parse_config_file(fn, this);
}

void AEKAVD::Options::set_is_daemon(bool v)
{
    isdaemon = v;
}

void AEKAVD::Options::set_syslog_perror(bool v)
{
    if (v)
        syslogopts |= LOG_PERROR;
    else
        syslogopts &= ~LOG_PERROR;
}

void AEKAVD::Options::set_syslog_facility(int v)
{
    syslogfacility = v;
}

void AEKAVD::Options::set_pid_file(const std::string& v)
{
    pidfile = v;
}

void AEKAVD::Options::set_kav_key_path(const std::string& v)
{
    kavkeypath = v;
}

void AEKAVD::Options::set_kav_base_path(const std::string& v)
{
    kavbasepath = v;
}

void AEKAVD::Options::set_listen_addr(uint32_t v)
{
    naddr = v;
}

void AEKAVD::Options::set_listen_port(uint16_t v)
{
    port = v;
}

void AEKAVD::Options::set_socket(const std::string& s)
{
    unix_socket = s;
}

void AEKAVD::Options::set_stream_limit(uint32_t limit)
{
    streamlimit = limit;
}

void AEKAVD::Options::set_kav_info_file(const std::string& v)
{
    kavinfofile = v;
}

void AEKAVD::Options::set_log_found_viruses(bool v)
{
    logfoundviruses = v;
}

void AEKAVD::parse_config_file(const std::string& fn, Options *options)
{
    std::ifstream is(fn.c_str());
    if (!is)
        error<std::runtime_error>("can not open file "+fn, strerror(errno));

    enum States { WAIT_KEYWORD, WAIT_EQUAL, WAIT_VALUE };

    bool exit = false;
    int state = WAIT_KEYWORD;
    int keyword = KW_UNKNOWN;
    while (!exit) {
        std::string s;
        Token token;
        if (is.eof())
            token = Token(TOK_EOF, 0, "<<EOF>>");
        else {
            is >> s;
            if (s.size() == 0) continue;
            token = string_to_token(s);
        }
        switch (state) {
        case WAIT_KEYWORD:
            switch (token.type) {
            case TOK_EOF:
                exit = true;
                break;
            case TOK_KEYWORD:
                keyword = token.int_val;
                state = WAIT_EQUAL;
                break;
            default:
                syntax_error("keyword", s);
                break;
            }
            break;
        case WAIT_EQUAL:
            switch (token.type) {
            case TOK_EQUAL:
                state = WAIT_VALUE;
                break;
            default:
                syntax_error("=", s);
                break;
            }
            break;
        case WAIT_VALUE:
            switch (token.type) {
            case TOK_KEYWORD:
            case TOK_STRING:
                set_option_value(keyword, token.str_val, options);
                state = WAIT_KEYWORD;
                break;
            default:
                break;
            }
            break;
        default:
            error<std::runtime_error>("invalid parsing state", state);
            break;
        }
    }
}

AEKAVD::Token AEKAVD::string_to_token(const std::string& s)
{
    for (int i=KW_FIRST; i<KW_NUM; ++i) {
        if (keyword_str[i] == s)
            return Token(TOK_KEYWORD, i, s);
    }

    if (s == "=")
        return Token(TOK_EQUAL, '=', s);

    return Token(TOK_STRING, 0, s);
}

void AEKAVD::set_option_value(int keyword, const std::string& val, Options *options)
{
    switch (keyword) {
    case KW_LISTEN_ADDR:
        set_listen_addr(val, options);
        break;
    case KW_LISTEN_PORT:
        set_listen_port(val, options);
        break;
    case KW_UNIX_SOCKET:
        set_unix_socket(val, options);
        break;
    case KW_STREAM_LIMIT:
        set_stream_limit(val, options);
        break;
    case KW_KAV_LICENCE_PATH:
        options->set_kav_key_path(val);
        break;
    case KW_KAV_BASES_PATH:
        options->set_kav_base_path(val);
        break;
    case KW_DAEMON_MODE:
        set_daemon_mode(val, options);
        break;
    case KW_PID_FILE:
        options->set_pid_file(val);
        break;
    case KW_SYSLOG_PERROR:
        set_syslog_perror(val, options);
        break;
    case KW_SYSLOG_FACILITY:
        set_syslog_facility(val, options);
        break;
    case KW_KAV_INFO_FILE:
        options->set_kav_info_file(val);
        break;
    case KW_LOG_FOUND_VIRUSES:
        set_log_found_viruses(val, options);
        break;
    default:
        error<std::runtime_error>("bad keyword index", keyword);
        break;
    }
}

void AEKAVD::set_listen_addr(const std::string& val, Options *options)
{
    struct in_addr addr;
    if (inet_aton(val.c_str(), &addr) == 0)
        error<std::invalid_argument>("invalid IP address", val);

    options->set_listen_addr(addr.s_addr);
}

void AEKAVD::set_listen_port(const std::string& val, Options *options)
{
    unsigned long v = strtoul(val.c_str(), 0, 0);
    if (v > 65535)
        error<std::invalid_argument>("port value is too big", val);

    options->set_listen_port(uint16_t(v));
}

void AEKAVD::set_unix_socket(const std::string& val, Options *options)
{
    if(val.size() > UNIX_PATH_MAX)
        error<std::invalid_argument>("too long unix socket", val);

    options->set_socket(val);
}

void AEKAVD::set_stream_limit(const std::string& val, Options *options)
{
    unsigned long v = strtoul(val.c_str(), 0, 0);
    if(v > STREAM_LIMIT)
        error<std::invalid_argument>("stream limit value is too big", val);

    options->set_stream_limit(uint32_t(v));
}

void AEKAVD::set_daemon_mode(const std::string& val, Options *options)
{
    bool v  = (strcasecmp("true", val.c_str()) == 0) ? true : false;

    options->set_is_daemon(v);
}

void AEKAVD::set_log_found_viruses(const std::string& val, Options *options)
{
    bool v  = (strcasecmp("true", val.c_str()) == 0) ? true : false;

    options->set_log_found_viruses(v);
}

void AEKAVD::set_syslog_perror(const std::string& val, Options *options)
{
    bool v  = (strcasecmp("true", val.c_str()) == 0) ? true : false;

    options->set_syslog_perror(v);
}

void AEKAVD::set_syslog_facility(const std::string& val, Options *options)
{
    for (int i=0; i<SLF_NUM; ++i) {
        if (strcasecmp(syslog_facility_tab[i].str, val.c_str()) == 0) {
            options->set_syslog_facility(syslog_facility_tab[i].val);
            return;
        }
    }

    error<std::invalid_argument>("invalid syslog facility", val);
}

void AEKAVD::syntax_error(const std::string& expected, const std::string& got)
{
    std::stringstream ss;
    ss << "syntax error: expected: " << expected << "; got: " << got;
    throw std::invalid_argument(ss.str());
}

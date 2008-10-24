// -*- C++ -*-
//
// Example of KAV Daemon
//
// Options and config file parsing
// Interface
//
//

#ifndef AEKVAD_OPTIONS_H
#define AEKVAD_OPTIONS_H


#include <stdint.h>
#include <string>


namespace AEKAVD {

    class Options {
    public:
        Options(const std::string&);

        bool               is_daemon()         const;
        int                syslog_options()    const;
        int                syslog_facility()   const;
        const std::string& pid_file()          const;
        const std::string& kav_key_path()      const;
        const std::string& kav_base_path()     const;
        uint32_t           listen_addr()       const;
        uint16_t           listen_port()       const;
        const std::string& kav_info_file()     const;
        bool               log_found_viruses() const;

        void set_is_daemon(bool);
        void set_syslog_perror(bool);
        void set_syslog_facility(int);
        void set_pid_file(const std::string&);
        void set_kav_key_path(const std::string&);
        void set_kav_base_path(const std::string&);
        void set_listen_addr(uint32_t);
        void set_listen_port(uint16_t);
        void set_kav_info_file(const std::string&);
        void set_log_found_viruses(bool);

    private:
        uint32_t    naddr;                      // in network byte order
        uint16_t    port;
        bool        isdaemon;
        std::string kavkeypath;
        std::string kavbasepath;
        std::string pidfile;
        int         syslogopts;
        int         syslogfacility;
        std::string kavinfofile;
        bool        logfoundviruses;
    };


    //
    // inlines
    //
    inline bool               Options::is_daemon()         const { return isdaemon;        }
    inline int                Options::syslog_options()    const { return syslogopts;      }
    inline int                Options::syslog_facility()   const { return syslogfacility;  }
    inline const std::string& Options::pid_file()          const { return pidfile;         }
    inline const std::string& Options::kav_key_path()      const { return kavkeypath;      }
    inline const std::string& Options::kav_base_path()     const { return kavbasepath;     }
    inline uint32_t           Options::listen_addr()       const { return naddr;           }
    inline uint16_t           Options::listen_port()       const { return port;            }
    inline const std::string& Options::kav_info_file()     const { return kavinfofile;     }
    inline bool               Options::log_found_viruses() const { return logfoundviruses; }
}

#endif  // AEKVAD_OPTIONS_H

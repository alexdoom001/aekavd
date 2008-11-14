// -*- C++ -*-
//
// Example of KAV Daemon
//
// Pid file
// Interface
//
//

#ifndef AEKAVD_PIDFILE_H
#define AEKAVD_PIDFILE_H


#include <string>


namespace AEKAVD {

    class Pid_file {
    public:
        Pid_file(const std::string&);
        void Pid_file_remove();

    private:
        std::string fn;
    };
}

#endif  // AEKAVD_PIDFILE_H

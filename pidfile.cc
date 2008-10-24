// -*- C++ -*-
//
// Example of KAV Daemon
//
// Pid file
// Implementation
//
//


#include <unistd.h>
#include <sys/types.h>
#include <errno.h>
#include <string.h>
#include <stdexcept>
#include <sstream>
#include <fstream>
#include "pidfile.h"


AEKAVD::Pid_file::Pid_file(const std::string& f)
    : fn(f)
{
    std::ofstream os(fn.c_str());
    if (!os) {
        std::stringstream ss;
        ss << "can not open pid file: " << fn << "; error: " << strerror(errno);
        throw std::invalid_argument(ss.str());
    }

    os << getpid() << std::endl;
    if (!os) {
        std::stringstream ss;
        ss << "can not write pid to file: " << fn << "; error: " << strerror(errno);
        throw std::runtime_error(ss.str());
    }
}

AEKAVD::Pid_file::~Pid_file()
{
    unlink(fn.c_str());
}

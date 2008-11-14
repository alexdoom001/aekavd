// -*- C++ -*-
//
// Example of KAV Daemon
//
// Session with client
// Interface
//
//

#ifndef AEKAVD_SESSION_H
#define AEKAVD_SESSION_H


#include <string>
#include <stdint.h>


namespace AEKAVD {
    extern void handle_session(int, uint32_t);
    extern int ctl_pipe[2];
}


#endif  // AEKAVD_SESSION_H

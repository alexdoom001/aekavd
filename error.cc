// -*- C++ -*-
//
// Example of KAV Daemon
//
// Error handling functions
// Implementaion
//
//


#include <string.h>
#include <string>
#include "error.h"

void AEKAVD::syscall_error(const std::string& func, int errcode)
{
    std::string msg = "call to '" + func + "' failed; error";
    error<std::runtime_error>(msg, strerror(errcode));
}

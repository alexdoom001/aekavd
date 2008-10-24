// -*- C++ -*-
//
// Example of KAV Daemon
//
// Error handling functions
// Intereface and template implementaion
//
//

#ifndef AEKAVD_ERROR_H
#define AEKAVD_ERROR_H


#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>


namespace AEKAVD {

    void syscall_error(const std::string&, int);


    template <typename Exception, typename Type>
    void error(const std::string& msg, Type param)
    {
        std::stringstream ss;
        ss << msg << ": " << param;
        throw Exception(ss.str());
    }

}

#endif  // AEKAVD_ERROR_H

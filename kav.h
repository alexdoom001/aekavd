// -*- C++ -*-
//
// Example of KAV Daemon
//
// Functions to work with KAV
// Interface
//
//

#ifndef AEKAVD_KAV_H
#define AEKAVD_KAV_H


#include <string>

namespace AEKAVD {

    struct Kav_info {
        std::string sdk_version;
        std::string num_records;
        std::string db_release_date;
        std::string used_key_file;
        std::string expire_date;
    };

    extern void kav_open(const std::string& kavkeypath, const std::string& kavbasepath, const std::string& kavtmppath);
    extern void kav_close();
    extern void kav_set_info(Kav_info&);
    extern std::string kav_scan_file(const std::string& filename, bool logviruses);
    extern std::string kav_scan_file(int);
    extern void *kav_reload_database(void*);

    extern bool reload_database_processing;
    extern pthread_mutex_t reload_database_mutex;
}


#endif // AEKAVD_KAV_H

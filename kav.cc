// -*- C++ -*-
//
// Example of KAV Daemon
//
// Functions to work with KAV
// Implementaion
//
//


#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <string>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <sys/stat.h>
#include <sdk8_unix_interface.h>
#include "error.h"
#include "options.h"
#include "kav.h"

#include "posixistream.h"

#ifdef UNICODE
#error UNICODE defined!
#endif

namespace {

    typedef std::pair<std::string, std::string> String_pair;
}


namespace AEKAVD {

    extern CALLBACK_RESULT kav_callback(unsigned long, unsigned long, unsigned long, const char *, const char *, unsigned long, unsigned long, void *);

    static std::string kav_init_res_str(HRESULT hr);
    static String_pair kav_scan_res_str(KAV_RESULT res);
}


void AEKAVD::kav_open(const std::string& kavkeypath, const std::string& kavbasepath)
{
    syslog(LOG_DEBUG, "session: trying to initialize KAV; kavkeypath: %s; kavbasepath: %s", kavkeypath.c_str(), kavbasepath.c_str());

    unsigned long scannertype = KAV_SHT_INPROC | KAV_SHT_ENGINE_KLAV | KAV_SHT_ENGINE_KLAVEMU;
    PFNCALLBACK pfn = kav_callback;

    HRESULT hr = kaveInitializeEx("/tmp", kavbasepath.c_str(), scannertype, 0, 0, 0, pfn, kavkeypath.c_str(), 1);
    if (FAILED(hr))
        error<std::invalid_argument>("KAV initialization failed", kav_init_res_str(hr));

    syslog(LOG_INFO, "KAV initialized successfully");
}

void AEKAVD::kav_close()
{
    HRESULT hr = kaveUninitialize();
    syslog(LOG_DEBUG, "KAV uninitialized; return code: %ld", (long)hr);
}

void AEKAVD::kav_set_info(Kav_info& kavinfo)
{
    // sdk version
    unsigned long verhi = 0;
    unsigned long verlo = 0;
    HRESULT hr = kaveGetVersion(&verhi, &verlo);
    if (FAILED(hr))
        error<std::runtime_error>("KAV get version failed", hr);
    std::ostringstream sdkveros;
    sdkveros << HIWORD(verhi) << "." << LOWORD(verhi) << "." << HIWORD(verlo) <<  "." << LOWORD(verlo);
    kavinfo.sdk_version = sdkveros.str();

    // database info
    KAV_DATABASES_INFO dbi;
    hr = kaveGetDatabasesInfo(&dbi);
    if (FAILED(hr))
        error<std::runtime_error>("KAV get database info failed", hr);

    std::ostringstream numrecsos;
    numrecsos << dbi.m_dwNumberOfViruses;
    kavinfo.num_records = numrecsos.str();

    std::ostringstream dbreleasedateos;
    dbreleasedateos << std::setw(2) << std::setfill('0') << dbi.m_dwLastUpdateDay   << '.'
                    << std::setw(2) << std::setfill('0') << dbi.m_dwLastUpdateMonth << '.'
                    << dbi.m_dwLastUpdateYear << " "
                    << std::setw(2) << std::setfill('0') << dbi.m_dwLastUpdateHour   << ':'
                    << std::setw(2) << std::setfill('0') << dbi.m_dwLastUpdateMinute << ':'
                    << std::setw(2) << std::setfill('0') << dbi.m_dwLastUpdateSecond;
    kavinfo.db_release_date = dbreleasedateos.str();

    // licence info
    KAV_LICENSE_INFO li;
    hr = kaveGetLicenseInfo(&li);
    if (FAILED(hr))
        error<std::runtime_error>("KAV get licence info: ", hr);

    std::ostringstream keyfileos;
    keyfileos << li.KeyFileName;
    kavinfo.used_key_file = keyfileos.str();

    std::ostringstream expiredateos;
    expiredateos << std::setw(2) << std::setfill('0') << li.dwExpDateDay   << '.'
                 << std::setw(2) << std::setfill('0') << li.dwExpDateMonth << '.'
                 << li.dwExpDateYear;
    kavinfo.expire_date = expiredateos.str();
}

std::string AEKAVD::kav_scan_file(const std::string& fn, bool logviruses)
{
    unsigned long  scanmode = KAV_O_M_PACKED | KAV_O_M_ARCHIVED | KAV_O_M_MAILPLAIN | KAV_O_M_HEURISTIC_LEVEL_SHALLOW;
    unsigned long  prty     = 10;
    KAV_RESULT     res      = KAV_S_R_NONSCANNED;

    HRESULT hr = kaveScanFile(fn.c_str(), prty, scanmode, KAV_SKIP, INFINITE, 0, 0, &res);
    if (SUCCEEDED(hr))
        syslog(LOG_DEBUG, "session: file scanned successfully: %s", fn.c_str());
    else {
        std::ostringstream s;
        s << "session: file scan failed; file: " << fn << "; error code: " << hr;
        throw std::runtime_error(s.str());
    }

    String_pair resstr = kav_scan_res_str(res);

    if (logviruses)
        syslog(LOG_DEBUG, "session: file scan finished; result: %s; returned to client: %s", resstr.first.c_str(), resstr.second.c_str());

    return fn + ": " + resstr.second;
}

std::string AEKAVD::kav_scan_file(int fd)
{
    unsigned long  scanmode = KAV_O_M_PACKED | KAV_O_M_ARCHIVED | KAV_O_M_MAILPLAIN | KAV_O_M_HEURISTIC_LEVEL_SHALLOW;
    unsigned long  prty     = 10;
    KAV_RESULT     res      = KAV_S_R_NONSCANNED;
    HRESULT hr;
    char fdstr[32];

    posixIStream stream(fd);
    hr = kaveScanStream(&stream, prty, scanmode, KAV_SKIP, INFINITE, 0, 0, &res);

    if (SUCCEEDED(hr))
        syslog(LOG_DEBUG, "session: file scanned successfully");
    else {
        std::ostringstream s;
        s << "session: file scan failed; error code: " << hr;
        throw std::runtime_error(s.str());
    }

    String_pair resstr = kav_scan_res_str(res);

    syslog(LOG_DEBUG, "session: file scan finished; result: %s; returned to client: %s", resstr.first.c_str(), resstr.second.c_str());

    snprintf(fdstr, sizeof(fdstr), "fd[%d]: ", fd);
    return fdstr + resstr.second;
}

CALLBACK_RESULT AEKAVD::kav_callback(unsigned long, unsigned long, unsigned long, const char *, const char *, unsigned long, unsigned long, void *)
{
    // stub, do nothing

    return CLBK_OK;
}

std::string AEKAVD::kav_init_res_str(HRESULT hr)
{
    std::string s;
    if (hr == KAV_E_MOD_NOT_FOUND)
        s = "KAV_E_MOD_NOT_FOUND: loader not found";
    else if (hr == KAV_E_INVALID_BASES)
        s = "KAV_E_INVALID_BASES: bases not found";
    else if (hr == KAV_E_PRODUCT_NOT_REGISTERED)
        s = "KAV_E_PRODUCT_NOT_REGISTERED: appinfo.kli missing or signature invalid";
    else if (hr == KAV_E_LICENSE_EXPIRED_OR_MISSING)
        s = "KAV_E_LICENSE_EXPIRED_OR_MISSING: no valid licence found or license expired";
    else {
        std::ostringstream ss;
        ss << hr;
        s = ss.str();
    }

    return s;
}

String_pair AEKAVD::kav_scan_res_str(KAV_RESULT res)
{
    std::string first;
    std::string second = "Malware FOUND";

    switch (res) {
    case KAV_S_R_CLEAN:
        first = "clean";
        second = "OK";
        break;
    case KAV_S_R_DISINFECTED:
        first = "disinfected";
        second = "OK";
        break;
    case KAV_S_R_SUSPICIOUS:
        first = "suspicious";
        second = "OK";
        break;
    case KAV_S_R_INFECTED:
        first =  "infected";
        break;
    case KAV_S_R_NONSCANNED:
        first = "non scanned";
        break;
    case KAV_S_R_CORRUPTED:
        first = "corrupted";
        break;
    case KAV_S_R_ACCESSDENIED:
        first = "access denied";
        break;
    case KAV_S_R_CANCELED:
        first = "canceled";
        break;
    case KAV_S_R_FAILURE:
        first = "failure";
        break;
    case KAV_S_R_SKIPPED:
        first = "skipped";
        break;
    case KAV_S_R_PASSWORD_PROTECTED:
        first = "password protected";
        break;
    default:
        { std::ostringstream ss;
          ss<<  "unknown result code: " << res;
          first = ss.str();
          break;
        }
    }

    return String_pair(first, second);
}

void *AEKAVD::kav_reload_database(void*)
{
    syslog(LOG_DEBUG, "KAV databases reload started...");
    HRESULT hr = kaveReloadDatabases();
    if (SUCCEEDED(hr)){
        Kav_info kavinfo;
        kav_set_info(kavinfo);
        syslog(LOG_DEBUG, "KAV databases reloaded successfully");
        syslog(LOG_INFO, "KAV database info: number of records: %s; virus db release date: %s", kavinfo.num_records.c_str(), kavinfo.db_release_date.c_str());
    }
    else {
        std::ostringstream s;
        s << "failed to reload databases: " << hr;
        throw std::runtime_error(s.str());
    }
	pthread_mutex_lock(&reload_database_mutex);
	reload_database_processing = false;
	pthread_mutex_unlock(&reload_database_mutex);
	return NULL;
}

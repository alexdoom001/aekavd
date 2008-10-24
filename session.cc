//
// Example of KAV Daemon
//
// Session with client
// Implementaion
//
//
//
// Imitates clamd session.
// Supports the followin commands:
//   SESSION\n  -- no response,
//   PING\n     -- PONG\n,
//   SCAN path  -- path: OK\n
//              -- ?
//   END        -- no response
//


#include <syslog.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <stdexcept>
#include <string>
#include <sstream>
#include "error.h"
#include "kav.h"
#include "session.h"

namespace AEKAVD {

    enum Session_command_code {
        SC_UNDEFINED   = -2,
        SC_UNSUPPORTED = -1,
        SC_SESSION     = 0,
        SC_PING,
        SC_END,
        SC_SCAN,
        SC_NUM
    };

    struct Command {
        int         code;
        std::string data;

        Command();
    };


    inline Command::Command() : code(SC_UNDEFINED) {}


    static Command     read_command(int sock);
    static bool        exec_command(int sock, const Command&, bool logviruses);
    static std::string read_line(int sock);
    static void        send_line(int sock, const std::string&);
}


void AEKAVD::handle_session(int sock, bool logviruses)
{
    syslog(LOG_INFO, "session: new session started");

    try {
        bool endsession = false;
        while (!endsession) {
            Command cmd = read_command(sock);
            endsession = exec_command(sock, cmd, logviruses);
        }
    }
    catch (std::exception& exc) {
        syslog(LOG_ERR, "session: session will be closed: got exception: %s", exc.what());
    }
    catch (...) {
        syslog(LOG_ERR, "session: session will be closed: got unknown exception");
    }

    syslog(LOG_INFO, "session: session closed");
}

AEKAVD::Command AEKAVD::read_command(int sock)
{
    std::string line = read_line(sock);
    syslog(LOG_DEBUG, "session: got command line: %s", line.c_str());

    Command cmd;
    if (line.size() == 0)
        cmd.code = SC_END;
    else if (line.find("SESSION") == 0)
        cmd.code = SC_SESSION;
    else if (line.find("PING") == 0)
        cmd.code = SC_PING;
    else if (line.find("END") == 0)
        cmd.code = SC_END;
    else if (line.find("SCAN") == 0) {
        cmd.code = SC_SCAN;
        // get filename to scan: strlen("SCAN")+1
        cmd.data = line.substr(5);
    } else {
        cmd.code = SC_UNSUPPORTED;
        cmd.data = line;
    }

    return cmd;
}

bool AEKAVD::exec_command(int sock, const Command& cmd, bool logviruses)
{
    bool endsession = false;

    switch (cmd.code) {
    case SC_END:
        syslog(LOG_DEBUG, "session: got END command");
        endsession = true;
        break;
    case SC_SESSION:
        syslog(LOG_DEBUG, "session: got SESSION command");
        // do nothing
        break;
    case SC_PING:
        syslog(LOG_DEBUG, "session: got PING command");
        send_line(sock, "PONG");
        break;
    case SC_SCAN:
        syslog(LOG_DEBUG, "session: got SCAN command; filename: %s", cmd.data.c_str());
        send_line(sock, kav_scan_file(cmd.data, logviruses));
        break;
    default:
        syslog(LOG_DEBUG, "session: got unsupported command: %s", cmd.data.c_str());
        endsession = true;
        break;
    }

    return endsession;
}

std::string AEKAVD::read_line(int sock)
{
    std::string line;
    bool stop = false;
    std::ostringstream s;
    while (!stop) {
        char buf[1];
        switch (read(sock, buf, 1)) {
        case -1:
            syscall_error("read", errno);
            break;
        case 0:
            // eof, connection was closed
            return std::string();
        default:
            if (buf[0] == '\n')
                stop = true;
            else
                line += buf[0];
            break;
        }
    }

    return line;
}

void AEKAVD::send_line(int sock, const std::string& l)
{
    std::string line = l + "\n";

    int size = line.size();
    int numsent = 0;
    while (numsent < size) {
        int count = write(sock, line.c_str()+numsent, size-numsent);
        if (count == -1)
            syscall_error("write", errno);
        numsent += count;
    }
}

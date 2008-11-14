//
// Example of KAV Daemon
//
// Session with client
// Implementaion
//
//
//
// Imitates clamd session.
// most of the code stolen from clamav-0.96.5
//
// Supports the followin commands:
//   RELOAD             -- not implemented
//   SHUTDOWN           -- not implemented
//   VERSION            -- not implemented
//   VERSIONCOMMANDS    -- not implemented
//   DETSTATSCLEAR      -- not implemented
//   DETSTATS           -- not implemented
//   STREAM             -- not implemented
//   MULTISCAN          -- not implemented
//   IDSESSION          -- not implemented
//   CONTSCAN           -- not implemented
//   STATS              -- not implemented
//   PING               -- PONG
//   SCANpath           -- path: OK or path: Malware FOUND
//   END                -- end current session
//                      --
//   bla-bla            -- UNKNOWN COMMAND
//

#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <syslog.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <limits.h>
#include <stdlib.h>
#include <fcntl.h>
#include <stdexcept>
#include <string>
#include <cstring>
#include <cstdio>
#include <sstream>
#include "error.h"
#include "kav.h"
#include "session.h"


#define TMP_FILE_TEMPLATE     "aevkavd_XXXXXX"
#define NEO_TMP_DIR           "/tmp"


#define CMD1 "SCAN"
/* #define CMD2 "RAWSCAN" */
#define CMD3 "QUIT" /* deprecated */
#define CMD4 "RELOAD"
#define CMD5 "PING"
#define CMD6 "CONTSCAN"
#define CMD7 "VERSION"
#define CMD8 "STREAM"
/*#define CMD9 "SESSION"*/
#define CMD10 "END"
#define CMD11 "SHUTDOWN"
/* #define CMD12 "FD" */
#define CMD13 "MULTISCAN"
#define CMD14 "FILDES"
#define CMD15 "STATS"
#define CMD16 "IDSESSION"
#define CMD17 "INSTREAM"
#define CMD18 "VERSIONCOMMANDS"
#define CMD19 "DETSTATSCLEAR"
#define CMD20 "DETSTATS"

namespace AEKAVD {

    enum commands {
        COMMAND_UNKNOWN = 0,
        COMMAND_SHUTDOWN = 1,
        COMMAND_RELOAD,
        COMMAND_END,
        COMMAND_SESSION,
        COMMAND_SCAN,
        COMMAND_PING,
        COMMAND_CONTSCAN,
        COMMAND_VERSION,
        COMMAND_STREAM,
        COMMAND_MULTISCAN,
        COMMAND_FILDES,
        COMMAND_STATS,
        /* new proto commands */
        COMMAND_IDSESSION,
        COMMAND_INSTREAM,
        COMMAND_COMMANDS,
        COMMAND_DETSTATSCLEAR,
        COMMAND_DETSTATS,
        /* internal commands */
        COMMAND_MULTISCANFILE,
        COMMAND_INSTREAMSCAN
    };

    enum mode {
        MODE_COMMAND,
        MODE_STREAM,
        MODE_WAITREPLY,
        MODE_WAITANCILL
    };

    struct fd_buf {
        char *buffer;
        size_t bufsize;
        size_t off;
        int fd;
        char term;
        int recvfd;
        enum mode mode;
        int dumpfd;
        char *dumpname;
        uint32_t chunksize;
        uint32_t quota;
        uint32_t currentquota;

        fd_buf(int socket, uint32_t streamlimit) :
            buffer(new char[PATH_MAX + 9]),
            /* plus extra space for a \0 so we can make sure every command is \0
             * terminated */
            bufsize(PATH_MAX+8),
            off(0),
            fd(socket),
            term('\0'),
            recvfd(-1),
            mode(MODE_COMMAND),
            dumpfd(-1),
            dumpname(NULL),
            chunksize(0),
            quota(streamlimit),
            currentquota(streamlimit){}
    };

    static void             send_line(const fd_buf * , const std::string&);
    static int              read_data(fd_buf *);
    static ssize_t          read_fd_data(fd_buf *);
    static const char*      parse_buf(fd_buf *, size_t *, int *, int *);
    static const char*      get_cmd(fd_buf *, size_t, size_t *, char *, int *);
    static int              chomp(char *);
    static enum commands    parse_command(const char *, const char **, int);
    static int              execute_command(fd_buf *, enum commands, const char *);
    static int              handle_stream(fd_buf *, int *, size_t *);
    static void             clear_instream_dump(fd_buf * buf);
    static const char *     gettmpdir();
    static int              gentempfd(char **);
    static int              writen(int, const void *, unsigned int);
}

void AEKAVD::handle_session(int sock, uint32_t streamlimit)
{
    syslog(LOG_INFO, "session: new session started, socket %u", sock);
    fd_buf buf(sock, streamlimit);

    try {
        int end_session = 0;
        while (!end_session) {
            int res = read_data(&buf);
            if(res == -1)
                syscall_error("read", errno);
            if(!res)
                break;

            size_t pos = 0;
            int error = 0;
            if (buf.mode == MODE_WAITANCILL) {
                buf.mode = MODE_COMMAND;
                syslog(LOG_DEBUG, "mode -> MODE_COMMAND");
            }

            while (!error && buf.fd != -1 &&
                   buf.buffer &&
                   pos < buf.off &&
                   buf.mode != MODE_WAITANCILL) {

                const char * cmd = parse_buf(&buf, &pos, &error, &end_session);

                if (buf.mode == MODE_COMMAND && !cmd)
                    break;
                if (buf.mode == MODE_STREAM) {
                    if (handle_stream(&buf,&error, &pos) == -1)
                        break;
                    else
                        continue;
                }
            }
            if (error) {
                syslog(LOG_NOTICE, "Shutting down socket after error (FD %d)", buf.fd);
                clear_instream_dump(&buf);
                close(buf.fd);
                buf.fd = -1;
                break;
            }
        }
    }
    catch (std::exception& exc) {
        syslog(LOG_ERR, "session: session will be closed: got exception: %s", exc.what());
        clear_instream_dump(&buf);
    }
    catch (...) {
        syslog(LOG_ERR, "session: session will be closed: got unknown exception");
        clear_instream_dump(&buf);
    }

    syslog(LOG_INFO, "session: session closed");
}

void AEKAVD::clear_instream_dump(fd_buf * buf)
{
    if (buf && buf->dumpfd != -1) {
        close(buf->dumpfd);
        if (buf->dumpname) {
            unlink(buf->dumpname);
            delete buf->dumpname;
        }
        buf->dumpfd = -1;
    }
}

ssize_t AEKAVD::read_fd_data(struct fd_buf *buf)
{
    if (buf->off >= buf->bufsize)
        return -1;

   /* Read the pending packet, it may contain more than one command, but
    * that is to the cmdparser to handle.
    * It will handle 1st command, and then move leftover to beginning of buffer
    */
    msghdr msg;
    cmsghdr *cmsg;
    union {
        unsigned char buff[CMSG_SPACE(sizeof(int))];
        cmsghdr hdr;
    } b;
    iovec iov[1];

    if (buf->recvfd != -1) {
        syslog(LOG_INFO, "Closing unclaimed FD");
        close(buf->recvfd);
        buf->recvfd = -1;
    }
    memset(&msg, 0, sizeof(msg));
    iov[0].iov_base = buf->buffer + buf->off;
    iov[0].iov_len = buf->bufsize - buf->off;
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;
    msg.msg_control = b.buff;
    msg.msg_controllen = sizeof(b.buff);

    ssize_t n = recvmsg(buf->fd, &msg, 0);
    if (n < 0)
        return -1;
    if (msg.msg_flags & MSG_TRUNC) {
        syslog(LOG_INFO, "Message truncated");
        return -1;
    }
    if (msg.msg_flags & MSG_CTRUNC) {
        if (msg.msg_controllen > 0)
            syslog(LOG_INFO, "Control message truncated");
        else
            syslog(LOG_INFO, "Control message truncated, no control data received");
        return -1;
    }
    if (msg.msg_controllen) {
        for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL;
             cmsg = CMSG_NXTHDR(&msg, cmsg)) {
            if (cmsg->cmsg_len == CMSG_LEN(sizeof(int)) &&
                cmsg->cmsg_level == SOL_SOCKET &&
                cmsg->cmsg_type == SCM_RIGHTS) {
                if (buf->recvfd != -1) {
                    syslog(LOG_INFO, "Unclaimed file descriptor received. closing");
                    close(buf->recvfd);
                }
                buf->recvfd = *(reinterpret_cast<int *>(CMSG_DATA(cmsg)));
                syslog(LOG_DEBUG, "File descriptor received");
            }
        }
    }
    buf->off += n;
    return n;
}

int AEKAVD::read_data(fd_buf * sock_buf)
{
    fd_set readfdset;
    FD_ZERO(&readfdset);
    FD_SET(sock_buf->fd, &readfdset);
    FD_SET(ctl_pipe[0], &readfdset);

    for(;;) {
        int rc = select(FD_SETSIZE, &readfdset, NULL, NULL, NULL);
        if (rc < 0) {
            if (errno == EINTR)
                syslog(LOG_DEBUG, "select was interrutped with signal; resuming");
            else
                syscall_error("select", errno);
        } else if (rc > 0) {
            if (FD_ISSET(ctl_pipe[0], &readfdset))
                return 0;
            if (FD_ISSET(sock_buf->fd, &readfdset))
                return read_fd_data(sock_buf);
        } // else rc == 0 - timeout
    }
    //should never happen
    return 0;
}

void AEKAVD::send_line(const fd_buf * buf, const std::string& l)
{
    std::string line = l + buf->term;

    int size = line.size();
    int numsent = 0;
    while (numsent < size) {
        int count = write(buf->fd, line.c_str() + numsent, size - numsent);
        if (count == -1)
            syscall_error("write", errno);
        numsent += count;
    }
}

const char * AEKAVD::parse_buf(fd_buf * buf, size_t * ppos, int * error, int * end_session)
{
    const char *cmd = NULL;
    int rc;
    size_t cmdlen;
    char term;
    int oldstyle;
    size_t pos = *ppos;
    /* Parse & execute commands */
    while ((buf->mode == MODE_COMMAND) &&
           (cmd = get_cmd(buf, pos, &cmdlen, &term, &oldstyle)) != NULL) {
        const char *argument;
        enum commands cmdtype = parse_command(cmd, &argument, oldstyle);
        buf->term = term;
        syslog(LOG_DEBUG, "got command %s (%u, %u), argument: %s\n",
               cmd, (unsigned)cmdlen, (unsigned)cmdtype, argument ? argument : "");
        if(cmdtype == COMMAND_END){
            *end_session = 1;
            pos += cmdlen+1;
            break;
        }
        if (cmdtype == COMMAND_FILDES) {
            if (buf->buffer + buf->off <= cmd + strlen("FILDES\n")) {
                /* we need the extra byte from recvmsg */
                buf->mode = MODE_WAITANCILL;
                /* put term back */
                buf->buffer[pos + cmdlen] = term;
                cmdlen = 0;
                syslog(LOG_DEBUG, "RECVTH: mode -> MODE_WAITANCILL");
                break;
            }
            /* eat extra \0 for controlmsg */
            cmdlen++;
            syslog(LOG_DEBUG, "RECVTH: FILDES command complete");
        }

        if (cmdtype && (rc = execute_command(buf, cmdtype, argument)) < 0) {
            syslog(LOG_NOTICE, "Command execute failed");
            *error = 1;
        }
        pos += cmdlen+1;
        if (buf->mode == MODE_STREAM)
            syslog(LOG_DEBUG, "Receive thread: INSTREAM");
        if (buf->mode != MODE_COMMAND) {
            syslog(LOG_DEBUG, "Breaking command loop, mode is no longer MODE_COMMAND");
            break;
        }
    }
    *ppos = pos;
    if (!*error) {
        /* move partial command to beginning of buffer */
        if (pos < buf->off) {
            memmove (buf->buffer, &buf->buffer[pos], buf->off - pos);
            buf->off -= pos;
        } else
            buf->off = 0;
        if (buf->off)
            syslog(LOG_DEBUG, "Moved partial command: %lu", (unsigned long)buf->off);
        else
            syslog(LOG_DEBUG, "Consumed entire command");
    }
    *ppos = pos;
    return cmd;
}

/*
 * zCOMMANDS are delimited by \0
 * nCOMMANDS are delimited by \n
 * Old-style non-prefixed commands are one packet, optionally delimited by \n,
 * with trailing \r|\n ignored
 */
const char * AEKAVD::get_cmd(fd_buf * buf, size_t off, size_t * len, char * term, int * oldstyle)
{
    char *pos;
    if (!buf->off || off >= buf->off) {
        *len = 0;
        return NULL;
    }

    *term = '\n';
    switch (buf->buffer[off]) {
        /* commands terminated by delimiters */
        case 'z':
            *term = '\0';
        case 'n':
            pos = (char*)memchr(buf->buffer + off, *term, buf->off - off);
            if (!pos) {
                /* we don't have another full command yet */
                *len = 0;
                return NULL;
            }
            *pos = '\0';
            if (*term) {
                *len = chomp(buf->buffer + off);
            } else {
                *len = pos - buf->buffer - off;
            }
            *oldstyle = 0;
            return buf->buffer + off + 1;
        default:
            /* one packet = one command */
            if (off)
                return NULL;
            pos = (char*)memchr(buf->buffer, '\n', buf->off);
            if (pos) {
                *len = pos - buf->buffer;
                *pos = '\0';
            } else {
                *len = buf->off;
                buf->buffer[buf->off] = '\0';
            }
            chomp(buf->buffer);
            *oldstyle = 1;
            return buf->buffer;
    }
}

/*
 * Remove trailing NL and CR characters from the end of the given string.
 * Return the new length of the string (ala strlen)
 */
int AEKAVD::chomp(char * string)
{
    int l;
    if(string == NULL)
        return -1;
    l  = strlen(string);
    if(l == 0)
        return 0;
    --l;
    while((l >= 0) && ((string[l] == '\n') || (string[l] == '\r')))
        string[l--] = '\0';
    return l + 1;
}

static struct {
    const char *cmd;
    const size_t len;
    enum AEKAVD::commands cmdtype;
    int need_arg;
    int support_old;
    int enabled;
} commands_list[] = {
    {CMD1,  sizeof(CMD1)-1,	AEKAVD::COMMAND_SCAN,	    1,	1, 0},
    {CMD3,  sizeof(CMD3)-1,	AEKAVD::COMMAND_SHUTDOWN,   0,	1, 0},
    {CMD4,  sizeof(CMD4)-1,	AEKAVD::COMMAND_RELOAD,	    0,	1, 0},
    {CMD5,  sizeof(CMD5)-1,	AEKAVD::COMMAND_PING,	    0,	1, 0},
    {CMD6,  sizeof(CMD6)-1,	AEKAVD::COMMAND_CONTSCAN,   1,	1, 0},
    /* must be before VERSION, because they share common prefix! */
    {CMD18, sizeof(CMD18)-1,	AEKAVD::COMMAND_COMMANDS,   0,	0, 1},
    {CMD7,  sizeof(CMD7)-1,	AEKAVD::COMMAND_VERSION,    0,	1, 1},
    {CMD8,  sizeof(CMD8)-1,	AEKAVD::COMMAND_STREAM,	    0,	1, 1},
    {CMD10, sizeof(CMD10)-1,	AEKAVD::COMMAND_END,	    0,	0, 1},
    {CMD11, sizeof(CMD11)-1,	AEKAVD::COMMAND_SHUTDOWN,   0,	1, 1},
    {CMD13, sizeof(CMD13)-1,	AEKAVD::COMMAND_MULTISCAN,  1,	1, 1},
    {CMD14, sizeof(CMD14)-1,	AEKAVD::COMMAND_FILDES,	    0,	1, 1},
    {CMD15, sizeof(CMD15)-1,	AEKAVD::COMMAND_STATS,	    0,	0, 1},
    {CMD16, sizeof(CMD16)-1,	AEKAVD::COMMAND_IDSESSION,  0,	0, 1},
    {CMD17, sizeof(CMD17)-1,	AEKAVD::COMMAND_INSTREAM,   0,	0, 1},
    {CMD19, sizeof(CMD19)-1,	AEKAVD::COMMAND_DETSTATSCLEAR,	0, 1, 1},
    {CMD20, sizeof(CMD20)-1,	AEKAVD::COMMAND_DETSTATS,   0, 1, 1}
};


enum AEKAVD::commands AEKAVD::parse_command(const char *cmd, const char **argument, int oldstyle)
{
    syslog(LOG_DEBUG, "parce_command cmd: %s", cmd);
    size_t i;
    *argument = NULL;
    if(!cmd)
        return COMMAND_UNKNOWN;
    for (i=0; i < sizeof(commands_list)/sizeof(commands_list[0]); i++) {
        const size_t len = commands_list[i].len;
        if (!strncmp(cmd, commands_list[i].cmd, len)) {
            const char *arg = cmd + len;
            if (commands_list[i].need_arg) {
                if (!*arg) {/* missing argument */
                    syslog(LOG_NOTICE, "Command %s missing argument!", commands_list[i].cmd);
                    return COMMAND_UNKNOWN;
                }
                *argument = arg+1;
            } else {
                if (*arg) {/* extra stuff after command */
                    syslog(LOG_NOTICE, "Command %s has trailing garbage!", commands_list[i].cmd);
                    return COMMAND_UNKNOWN;
                }
                *argument = NULL;
            }
            if (oldstyle && !commands_list[i].support_old) {
                syslog(LOG_NOTICE, "Command sent as old-style when not supported: %s", commands_list[i].cmd);
                return COMMAND_UNKNOWN;
            }
            return commands_list[i].cmdtype;
        }
    }
    return COMMAND_UNKNOWN;
}

/* returns:
 *  <0 for error
 *     -1 out of memory
 *     -2 other
 *   0 for async dispatched
 *   1 for command completed (connection can be closed)
 */
int AEKAVD::execute_command(fd_buf * conn, enum commands cmd, const char *argument)
{
    syslog(LOG_DEBUG, "execute command type: %d", cmd);
    std::string answer;
    switch (cmd) {
        case COMMAND_SHUTDOWN:
        case COMMAND_RELOAD:
        case COMMAND_VERSION:
        case COMMAND_COMMANDS:
        case COMMAND_DETSTATSCLEAR:
        case COMMAND_DETSTATS:
        case COMMAND_STREAM:
        case COMMAND_MULTISCAN:
        case COMMAND_IDSESSION:
        case COMMAND_CONTSCAN:
        case COMMAND_STATS:
            answer = "not implemented";
            break;
        case COMMAND_INSTREAM:
            conn->dumpfd = gentempfd(&conn->dumpname);
            if (conn->dumpfd == -1)
                return conn->dumpfd;
            syslog(LOG_DEBUG, "tmp file name: %s", conn->dumpname);
            conn->currentquota = conn->quota;//FIXME//TODO
            conn->mode = MODE_STREAM;
            return 1;
        case COMMAND_PING:
            answer = "PONG";
            break;
        case COMMAND_FILDES:
            syslog(LOG_DEBUG, "fildes command execution, fd: %u", conn->recvfd);
            answer = kav_scan_file(conn->recvfd);
            break;
        case COMMAND_SCAN:
            answer = kav_scan_file(argument, true);
            break;
        case COMMAND_INSTREAMSCAN://scan file from INSTREAM
            syslog(LOG_DEBUG, "scan instream file: %s", conn->dumpname);
            answer = kav_scan_file(conn->dumpname, true);
            clear_instream_dump(conn);
            break;
        /*case COMMAND_UNKNOWN:*/
        default:
            answer = "UNKNOWN COMMAND";
    }
    send_line(conn, answer);
    return 1;
}

int AEKAVD::handle_stream(fd_buf *buf, int *error, size_t *ppos)
{
    int rc;
    size_t pos = *ppos;
    size_t cmdlen;

    syslog(LOG_DEBUG, "mode == MODE_STREAM");
    /* we received a chunk, set readtimeout */
    if (!buf->chunksize) {
        /* read chunksize */
        if (buf->off >= 4) {
            uint32_t cs = *(uint32_t*)buf->buffer;
            buf->chunksize = ntohl(cs);
            syslog(LOG_DEBUG, "Got chunksize: %u", buf->chunksize);
            if (!buf->chunksize) {
                /* chunksize 0 marks end of stream */
                buf->mode = MODE_COMMAND;
                syslog(LOG_DEBUG, "chunk complete");

                if ((rc = execute_command(buf, COMMAND_INSTREAMSCAN, NULL)) < 0) {
                    syslog(LOG_NOTICE, "Command execute failed");
                    *error = 1;
                } else {
                    pos = 4;
                    memmove (buf->buffer, &buf->buffer[pos], buf->off - pos);
                    buf->off -= pos;
                    *ppos = 0;
                    return 0;
                }
            }
            if (buf->chunksize > buf->currentquota) {
                syslog(LOG_NOTICE, "INSTREAM: Size limit reached, (requested: %lu, max: %lu)",
                    (unsigned long)buf->chunksize, (unsigned long)buf->quota);
                send_line(buf, "INSTREAM size limit exceeded.");
                *error = 1;
                *ppos = pos;
                return -1;
            } else {
                buf->currentquota -= buf->chunksize;
            }
            pos = 4;
        } else
            return -1;
    } else
        pos = 0;
    if (pos + buf->chunksize < buf->off)
        cmdlen = buf->chunksize;
    else
        cmdlen = buf->off - pos;
    buf->chunksize -= cmdlen;
    if (writen(buf->dumpfd, buf->buffer + pos, cmdlen) < 0) {
        send_line(buf, "Error writing to temporary file");
        syslog(LOG_NOTICE, "INSTREAM: Can't write to temporary file");
        *error = 1;
    }
    syslog(LOG_DEBUG, "Processed %lu bytes of chunkdata", cmdlen);
    pos += cmdlen;
    if (pos == buf->off) {
        buf->off = 0;
    }
    *ppos = pos;
    return 0;
}

int AEKAVD::gentempfd(char **name)
{
    const char * dir = gettmpdir();
    int size = strlen(dir) + strlen(TMP_FILE_TEMPLATE) + 2;
    *name = new char[size];
    sprintf(*name, "%s/%s", dir, TMP_FILE_TEMPLATE);

    int fd = mkostemp(*name, O_RDWR|O_CREAT|O_TRUNC|O_EXCL);
    if(fd == -1){
        delete[] *name;
        *name = NULL;
        syscall_error("create tmp file failed: mkostemp", errno);
    }
    return fd;
}

const char * AEKAVD::gettmpdir(void)
{
    const char * tmpdir;
    if(!(tmpdir = getenv("TMPDIR")))
        tmpdir = NEO_TMP_DIR;
    return tmpdir;
}

int AEKAVD::writen(int fd, const void *buff, unsigned int count)
{
    unsigned int todo = count;
    const unsigned char * current = (const unsigned char *) buff;

    do {
        int retval = write(fd, current, todo);
        if (retval < 0) {
            if (errno == EINTR)
                continue;
            syslog(LOG_NOTICE, "writen: write error: %s", strerror(errno));
            return -1;
        }
        todo -= retval;
        current += retval;
    } while (todo > 0);

    return count;
}

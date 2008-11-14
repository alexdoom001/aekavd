#include <stdio.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <string.h>
#include <syslog.h>
#include <arpa/inet.h>
#include <unistd.h> 
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <netdb.h>

#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>

void test_unix_socket(char *unix_socket_path, const std::string& path);
void test_tcp_socket(int port);

template <typename Exception, typename Type>
void error(const std::string& msg, Type param)
{
    std::stringstream ss;
    ss << msg << ": " << param;
    throw Exception(ss.str());
}

void syscall_error(const std::string& func, int errcode)
{
    std::string msg = "call to '" + func + "' failed; error";
    error<std::runtime_error>(msg, strerror(errcode));
}

int open_unix_socket(const std::string& path)
{
    int sock = socket(PF_UNIX, SOCK_STREAM, 0);
    if (sock < 0)
        syscall_error("socket", errno);
    
    sockaddr_un name;
    name.sun_family = AF_UNIX;
    strcpy(name.sun_path, path.c_str());
    if (connect(sock, (struct sockaddr *) &name, sizeof(name)) != 0) {
        std::ostringstream s;
        s << "failed to connect socket: " << path << ": " << strerror(errno);
        throw std::runtime_error(s.str());
    }   
   
    return sock;
}

int open_tcp_socket(uint16_t port)
{
    struct hostent *host;
    host = gethostbyname("localhost");

    int sock = socket(PF_INET, SOCK_STREAM, 0);
    if (sock < 0)
        syscall_error("socket", errno);

    struct sockaddr_in name;
    name.sin_family = AF_INET;
    name.sin_port = htons(port);
    bcopy((char *)host->h_addr, (char *)&name.sin_addr.s_addr, host->h_length);
    if (connect(sock, (struct sockaddr *) &name, sizeof(name)) != 0) {
        std::ostringstream s;
        s << "failed to connect socket: " << strerror(errno);
        throw std::runtime_error(s.str());
    }

    return sock;
}

//code from check_clamd.c clamav-0.96.5
static int sendmsg_fd(int sockd, const char *mesg, size_t msg_len, int fd, int singlemsg)
{
    struct msghdr msg;
    struct cmsghdr *cmsg;
    unsigned char fdbuf[CMSG_SPACE(sizeof(int))];
    char dummy[BUFSIZ];
    struct iovec iov[1];
    int rc;
    
    if (!singlemsg) {
        /* send FILDES\n and then a single character + ancillary data */
        dummy[0] = '\0';
        iov[0].iov_base = dummy;
        iov[0].iov_len = 1;
    } else {
        /* send single message with ancillary data */
        if(msg_len > sizeof(dummy)-1){
            printf("message too large\n");
            return -1;
        }
        memcpy(dummy, mesg, msg_len);
        dummy[msg_len] = '\0';
        iov[0].iov_base = dummy;
        iov[0].iov_len = msg_len + 1;
    }
    
    memset(&msg, 0, sizeof(msg));
    msg.msg_control = fdbuf;
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;
    msg.msg_controllen = CMSG_LEN(sizeof(int));
    
    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    *(int *)CMSG_DATA(cmsg) = fd;
    
    if (!singlemsg) {
        rc = send(sockd, mesg, msg_len, 0);
        if (rc == -1)
            return rc;
    }
    
    return sendmsg(sockd, &msg, 0);
}

void print_optons(void)
{
    printf("options:\n");
    printf("-unix_socket <socket file> - test unix socket\n");
    printf("-scan_file <path> - scan file path\n");
    printf("-tcp_port <port> - test tcp socket\n");
}

int main(int argc, char * argv[])
{   
    int tcp_port = 0;
    int unix_socket = 0;
    char *unix_socket_path;
    int scan_file = 0;
    char *scan_file_path;

    argc--;
    argv++;

    if(!argc)
        print_optons();

    while(argc >= 1) {
        if(strcmp(*argv,"-unix_socket") == 0) {
            if (--argc < 1) goto end;
            else
                unix_socket_path = *(++argv);
            unix_socket = 1;
        }
        else if(strcmp(*argv,"-tcp_port") == 0) {
            if (--argc < 1) goto end;
            else {
                tcp_port = atoi(*(++argv));
                if (tcp_port == 0) goto end;
             }
        }
        else if(strcmp(*argv,"-scan_file") == 0) {
            if (--argc < 1) goto end;
            else
                scan_file_path = *(++argv);
            scan_file = 1;
        }
        else if(strcmp(*argv,"-h") == 0) {
            print_optons();
            goto end;
        }
        else {
            print_optons();
            goto end;
            }
        argc--;
        argv++;
    }

    if(unix_socket && !scan_file) {
        print_optons();
        goto end;
    }

    try {
        if(unix_socket)
            test_unix_socket(unix_socket_path, scan_file_path);
        if(tcp_port)
            test_tcp_socket(tcp_port);
    }
    catch (std::exception& exc) {
        syslog(LOG_ERR, "session: session will be closed: got exception: %s", exc.what());
    }
    catch (...) {
        syslog(LOG_ERR, "session: session will be closed: got unknown exception");
    }

end:
    return 0;
}

void test_commands(int fd)
{
    char answer[1024];

    //check PING
    if(sendmsg_fd(fd, "PING", sizeof("PING"), 0, 1) == -1)
    sleep(10);
    memset(answer, 0, sizeof(answer));
    int res = read(fd, answer, 1024);
    printf("PING answer: %s", answer);

    //check INSTREAM
    char eicar1[] = "X5O!P%@AP[4\\PZX54(P^)7CC)7}";
    char eicar2[] = "$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

    //send(fd, "nINSTREAM\n", strlen("nINSTREAM\n"), 0);
    send(fd, "zINSTREAM\0", strlen("zINSTREAM") + 1, 0);

    char data[1024];
    int size = 0;
    int n_size = 0;

    size = strlen(eicar1);
    n_size = htonl(size);
    memcpy(data, &n_size, 4);
    memcpy(data + 4, eicar1, size);
    send(fd, data, size + 4, 0);

    size = strlen(eicar2);
    n_size = htonl(size);
    memcpy(data, &n_size, 4);
    memcpy(data + 4, eicar2, size);
    send(fd, data, size + 4, 0);

    size = 0;
    memcpy(data, &size, 4);
    send(fd, data, 4, 0);

    sleep(10);
    char answer1[1024];
    res = read(fd, answer1, 1024);
    printf("INSTREAM answer: %s\n", answer1);
}

void test_unix_socket(char *unix_socket_path, const std::string& path)
{
    char answer[1024];

    int fd = open_unix_socket(unix_socket_path);
    //check FILDES
    int scan_fd = open(path.c_str(), O_RDWR);
    if(scan_fd == -1) {
        printf("scan FILDES error\n");
        close(fd);
        return;
    }

    if(sendmsg_fd(fd, "zFILDES", sizeof("zFILDES"), scan_fd, 1) == -1)
    sleep(10);
    memset(answer, 0, sizeof(answer));
    read(fd, answer, 1024);
    printf("FILDES answer: %s\n", answer);

    test_commands(fd);

    close(scan_fd);
    close(fd);
}

void test_tcp_socket(int port)
{
    int fd = open_tcp_socket(port);
    test_commands(fd);
    close(fd);
}

#ifndef VIRUSTOTAL_POLLING_HTTPSERVER_H
#define VIRUSTOTAL_POLLING_HTTPSERVER_H

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pthread.h>
#include <stdlib.h>
#include <string>
#include <map>
#include "HttpConnection.h"

class HttpServer : public HttpConnection
{
private:
    HttpServer();

    static void sigchldHandler(int sig);

    void sendOkResponse(int sock);

    static std::map<pid_t, int> clientSockets;

public:
    static HttpServer& getInstance();

    ~HttpServer();
    void init();

    void handleConnection(int socket_desc);

    std::string handleMessage(const std::string& message, int sock);

    void startServer();

};


#endif //VIRUSTOTAL_POLLING_HTTPSERVER_H

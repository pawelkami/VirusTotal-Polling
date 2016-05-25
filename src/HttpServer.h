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
#include "HttpConnection.h"

class HttpServer : public HttpConnection
{
private:


    HttpServer();
public:
    static HttpServer& getInstance();

    ~HttpServer();
    void init();

    static void *connectionHandler(void *socket_desc);

    bool handleMessage(const std::string& message);


    void reply(int newSocket);


    void startServer();

};


#endif //VIRUSTOTAL_POLLING_HTTPSERVER_H

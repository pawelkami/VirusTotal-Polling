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

class HttpServer
{
private:

    int socketListen;
    struct sockaddr_in server;
    struct sockaddr_in client;

    void initialize();

public:

    HttpServer();
    ~HttpServer();

    static void *connectionHandler(void *socket_desc);
    static void handleMessage(const std::string& message);

    void reply(int newSocket);


    void startServer();

};


#endif //VIRUSTOTAL_POLLING_HTTPSERVER_H

#ifndef VIRUSTOTAL_POLLING_HTTPSERVER_H
#define VIRUSTOTAL_POLLING_HTTPSERVER_H

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pthread.h>
#include <stdlib.h>

class HttpServer
{
private:

    int socket_desc;
    int new_socket;
    int c;
    int *new_sock;
    struct sockaddr_in server;
    struct sockaddr_in client;
    char *message;

public:

    HttpServer();

    static void *connection_handler(void *socket_desc);

    void reply();

    void initialize();

    void startServer();

};


#endif //VIRUSTOTAL_POLLING_HTTPSERVER_H

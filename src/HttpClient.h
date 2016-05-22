#ifndef VIRUSTOTAL_POLLING_HTTPCLIENT_H
#define VIRUSTOTAL_POLLING_HTTPCLIENT_H

#include "Configuration.h"
#include "Logger.h"
#include "HttpResponse.h"
#include "HttpRequest.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <resolv.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <cstring>
#include <unistd.h>
#include <openssl/ssl.h>
#include <errno.h>

#define SSL_PORT 443

class HttpClient
{
private:
    int sock;

    SSL *conn;

    SSL_CTX *ssl_ctx;

    uint16_t port;

    bool isSSL;

public:
    HttpClient();
    ~HttpClient();

    void init();

    void sendMsg(const HttpRequest& request);

    HttpResponse receiveResponse();

};


#endif //VIRUSTOTAL_POLLING_HTTP_CLIENT_H

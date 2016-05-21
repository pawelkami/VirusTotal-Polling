#ifndef VIRUSTOTAL_POLLING_HTTPCLIENT_H
#define VIRUSTOTAL_POLLING_HTTPCLIENT_H

#include "Configuration.h"
#include "Logger.h"
#include "HttpRequest.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>


class HttpClient
{
private:
    int sock;

public:
    HttpClient();
    ~HttpClient();

    void init();

    void send(const HttpRequest& request);

    std::string receiveResponse();
};


#endif //VIRUSTOTAL_POLLING_HTTP_CLIENT_H
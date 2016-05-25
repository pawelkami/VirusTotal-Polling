#ifndef VIRUSTOTAL_POLLING_HTTPCLIENT_H
#define VIRUSTOTAL_POLLING_HTTPCLIENT_H

#include "Configuration.h"
#include "Logger.h"
#include "HttpResponse.h"
#include "HttpRequest.h"
#include "HttpConnection.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <resolv.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <cstring>
#include <openssl/ssl.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>

#define TIMEOUT 4

class HttpClient : public HttpConnection
{
private:

public:
    HttpClient();
    ~HttpClient();

    void init();

    HttpResponse receiveResponse();


};


#endif //VIRUSTOTAL_POLLING_HTTP_CLIENT_H

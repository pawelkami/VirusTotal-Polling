//
// Created by osboxes on 20/05/16.
//

#ifndef VIRUSTOTAL_POLLING_HTTPREQUEST_H
#define VIRUSTOTAL_POLLING_HTTPREQUEST_H

#include <map>
#include "Logger.h"

    enum HttpMethod
    {
        GET,
        HEAD,
        POST,
        PUT,
        DELETE,
        CONNECT,
        OPTIONS,
        TRACE
    };

class HttpRequest
{
private:
    // HTTP request header
    std::string request;

    // HTTP headers
    std::map<std::string, std::string> headers;

    // HTTP request body
    std::string body;

public:

    void putRequest(HttpMethod method, const std::string& selector);

    void putHeader(const std::string& key, const std::string& value);

    void putBody(const std::string& body);

    std::string getRequest();

};


#endif //VIRUSTOTAL_POLLING_HTTPREQUEST_H

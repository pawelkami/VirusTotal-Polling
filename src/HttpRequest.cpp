//
// Created by osboxes on 20/05/16.
//

#include "HttpRequest.h"

void HttpRequest::putRequest(HttpMethod method, const std::string &selector)
{
    std::string meth;
    switch(method)
    {
        case GET:
            meth = "GET";
            break;
        case HEAD:
            meth = "HEAD";
            break;
        case POST:
            meth = "POST";
            break;
        case PUT:
            meth = "PUT";
            break;
        case DELETE:
            meth = "DELETE";
            break;
        case CONNECT:
            meth = "CONNECT";
            break;
        case OPTIONS:
            meth = "OPTIONS";
            break;
        case TRACE:
            meth = "TRACE";
            break;
    }

    request = meth + " " + selector + " HTTP/1.1";
}

void HttpRequest::putHeader(const std::string &key, const std::string &value)
{
    headers[key] = value;
}

void HttpRequest::putBody(const std::string &body)
{
    this->body = body;
}

std::string HttpRequest::getRequest() const
{
    std::string fullRequest;
    fullRequest = request + "\r\n";

    for(auto& h : headers)
    {
        std::string header = h.first + ": " + h.second + "\r\n";

        fullRequest += header;
    }

    fullRequest += "\r\n";
    fullRequest += body;

    return fullRequest;
}









#include <sstream>
#include <vector>
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

    request = meth + " " + selector + " HTTP/1.1\r\n";
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
    fullRequest = request;

    for(auto& h : headers)
    {
        std::string header = h.first + ": " + h.second + "\r\n";

        fullRequest += header;
    }

    fullRequest += "\r\n";
    fullRequest += body;

    return fullRequest;
}

HttpRequest::HttpRequest(const std::string &req)
{
    buildRequest(req);
}

void HttpRequest::buildRequest(const std::string &req)
{
    std::stringstream ss;

    ss << req;

    std::string temp;
    std::getline(ss, temp);

    request = temp;

    while(std::getline(ss, temp) && temp.find(":") != std::string::npos)
    {
        std::string key = temp.substr(0, temp.find_first_of(":"));
        std::string value = temp.substr(temp.find_first_of(" ") + 1);
        putHeader(key, value);
    }

    if(headers.find("Content-Length") != headers.end())
    {
        int len = std::stoi(headers["Content-Length"]);
        body = req.substr(req.size()-len);
    }
    else
    {
        while(std::getline(ss, temp))
        {
            body += temp;
        }
    }

    putBody(body);
}

const std::string &HttpRequest::getBody()
{
    return body;
}

const std::string HttpRequest::getHeader(const std::string &key)
{
    return headers[key];
}


















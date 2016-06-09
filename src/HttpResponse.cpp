#include <sstream>
#include "HttpResponse.h"

HttpResponse::~HttpResponse()
{

}

void HttpResponse::buildResponse(const std::string &response)
{
    std::stringstream ss;
    ss << response;

    std::getline(ss, this->response);

    std::string temp;
    while(std::getline(ss, temp) && temp.find(":") != std::string::npos)
    {
        std::string key = temp.substr(0, temp.find_first_of(":"));
        std::string value = temp.substr(temp.find_first_of(" ") + 1);
        putHeader(key, value);
    }

    std::string body;
    while(std::getline(ss, temp))
    {
        body += temp;
    }

    putBody(body);
}

void HttpResponse::putHeader(const std::string &key, const std::string &value)
{
    headers[key] = value;
}

void HttpResponse::putBody(const std::string &body)
{
    this->body = body;
}

HttpResponse::HttpResponse(const std::string &response)
{
    buildResponse(response);
}

std::string HttpResponse::getResponseCode()
{
    std::string code;
    code = response.substr(response.find_first_of(' ') + 1);
    code = code.substr(0, code.find_first_of(' '));
    return code;
}

const std::string &HttpResponse::getBody()
{
    return body;
}

const std::string &HttpResponse::getHeader(const std::string &key) {
    return headers[key];
}

std::string HttpResponse::getResponse()
{
    std::stringstream ss;

    ss << response << "\r\n";

    for(auto& h : headers)
        ss << h.first << ": " << h.second << std::string("\r\n");

    ss << "\r\n";
    ss << body;

    return ss.str();
}


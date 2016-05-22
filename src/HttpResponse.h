
#ifndef VIRUSTOTAL_POLLING_HTTPRESPONSE_H
#define VIRUSTOTAL_POLLING_HTTPRESPONSE_H

#include <string>
#include <map>

class HttpResponse
{
private:
    // HTTP response header
    std::string response;

    // HTTP response headers
    std::map<std::string, std::string> headers;

    // HTTP response body
    std::string body;

    void buildResponse(const std::string& response);
public:
    HttpResponse(const std::string& response);

    ~HttpResponse();


    void putHeader(const std::string& key, const std::string& value);

    void putBody(const std::string& body);

    std::string getResponseCode();

    const std::string& getBody();

};


#endif //VIRUSTOTAL_POLLING_HTTPRESPONSE_H

#ifndef VIRUSTOTAL_POLLING_HTTPCLIENTEXCEPTION_H
#define VIRUSTOTAL_POLLING_HTTPCLIENTEXCEPTION_H


#include <exception>
#include <string>

class HttpClientException : public std::exception
{
public:

    explicit HttpClientException(const char* message): msg_(message){ }

    explicit HttpClientException(const std::string& message): msg_(message) {}

    virtual ~HttpClientException() throw() {}


    virtual const char* what() const throw()
    {
        return msg_.c_str();
    }

protected:

    std::string msg_;
};


#endif //VIRUSTOTAL_POLLING_HTTPCLIENTEXCEPTION_H

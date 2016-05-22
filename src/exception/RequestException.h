#ifndef VIRUSTOTAL_POLLING_RequestException_H
#define VIRUSTOTAL_POLLING_RequestException_H


#include <exception>
#include <string>

class RequestException : public std::exception
{
public:

    explicit RequestException(const char* message): msg_(message){ }

    explicit RequestException(const std::string& message): msg_(message) {}

    virtual ~RequestException() throw() {}


    virtual const char* what() const throw()
    {
        return msg_.c_str();
    }

protected:

    std::string msg_;
};


#endif //VIRUSTOTAL_POLLING_RequestException_H

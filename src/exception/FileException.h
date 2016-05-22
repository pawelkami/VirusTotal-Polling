#ifndef VIRUSTOTAL_POLLING_FILEEXCEPTION_H
#define VIRUSTOTAL_POLLING_FILEEXCEPTION_H

#include <exception>
#include <string>

class FileException : public std::exception
{
public:

    explicit FileException(const char* message): msg_(message){ }

    explicit FileException(const std::string& message): msg_(message) {}

    virtual ~FileException() throw() {}


    virtual const char* what() const throw()
    {
        return msg_.c_str();
    }

protected:

    std::string msg_;
};

#endif //VIRUSTOTAL_POLLING_FILEEXCEPTION_H






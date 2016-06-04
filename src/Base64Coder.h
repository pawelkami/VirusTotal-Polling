#ifndef VIRUSTOTAL_POLLING_BASE64CODER_H
#define VIRUSTOTAL_POLLING_BASE64CODER_H

#include <string>

class Base64Coder
{
private:

    const std::string base64_chars;

    bool is_base64(unsigned char c);

public:

    Base64Coder();

    std::string base64_encode(unsigned char const* , unsigned int len);

    std::string base64_decode(std::string const& s);

};

#endif //VIRUSTOTAL_POLLING_BASE64CODER_H

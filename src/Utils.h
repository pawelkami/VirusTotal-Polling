
#ifndef VIRUSTOTAL_POLLING_UTILS_H
#define VIRUSTOTAL_POLLING_UTILS_H


#include <iostream>
#include <string>
#include <stdio.h>
#include <time.h>
#include <utf8/utf8.h>

// format YYYY-MM-DD HH:mm:ss
const std::string currentDateTime();

unsigned int hextodec( const std::string &hex );

std::string base64_encode(const std::string &in);

std::string base64_decode(const std::string &in);

void fix_utf8_string(std::string& str);


#endif //VIRUSTOTAL_POLLING_UTILS_H


#ifndef VIRUSTOTAL_POLLING_UTILS_H
#define VIRUSTOTAL_POLLING_UTILS_H


#include <iostream>
#include <string>
#include <stdio.h>
#include <time.h>

// format YYYY-MM-DD HH:mm:ss
const std::string currentDateTime();

unsigned int hextodec( const std::string &hex );


#endif //VIRUSTOTAL_POLLING_UTILS_H

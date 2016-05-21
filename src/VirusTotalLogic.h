#ifndef VIRUSTOTAL_POLLING_VIRUSTOTALLOGIC_H
#define VIRUSTOTAL_POLLING_VIRUSTOTALLOGIC_H


#include <string>
#include "HttpClient.h"

class VirusTotalLogic
{
private:
    HttpClient http;

public:
    void initializeConnection();

    void sendData(const std::string& data);

    std::string parseResults(const std::string& html);

};


#endif //VIRUSTOTAL_POLLING_VIRUSTOTALLOGIC_H

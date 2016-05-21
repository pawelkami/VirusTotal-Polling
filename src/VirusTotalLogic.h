#ifndef VIRUSTOTAL_POLLING_VIRUSTOTALLOGIC_H
#define VIRUSTOTAL_POLLING_VIRUSTOTALLOGIC_H


#include <string>
#include "HttpClient.h"

class VirusTotalLogic
{
private:
    HttpClient http;

    std::string virusPath;

public:
    void setVirusPath(const std::string& path);

    void initializeConnection();

    void sendData(const std::string& data);

    std::string parseResults(const std::string& html);

    void saveResultsToFile(const std::string& results);

};


#endif //VIRUSTOTAL_POLLING_VIRUSTOTALLOGIC_H

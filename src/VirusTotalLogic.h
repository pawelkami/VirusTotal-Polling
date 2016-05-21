#ifndef VIRUSTOTAL_POLLING_VIRUSTOTALLOGIC_H
#define VIRUSTOTAL_POLLING_VIRUSTOTALLOGIC_H


#include <string>
#include "HttpClient.h"

class VirusTotalLogic
{
private:
    std::string boundary;
    std::string getFilename(const std::string& filePath);
    HttpClient http;

    std::string virusPath;

public:
    void setVirusPath(const std::string& path);

    std::string encodeData(const std::string& filePath);

    std::string getContentType();

    void initializeConnection();

    void sendData(const std::string& data);

    std::string parseResults(const std::string& html);

    void saveResultsToFile(const std::string& results);

};


#endif //VIRUSTOTAL_POLLING_VIRUSTOTALLOGIC_H

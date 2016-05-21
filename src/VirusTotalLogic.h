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

public:
    std::string encodeData(const std::string& filePath);

    std::string getContentType();

    void initializeConnection();

    void sendData(const std::string& data);

    std::string parseResults(const std::string& html);

};


#endif //VIRUSTOTAL_POLLING_VIRUSTOTALLOGIC_H

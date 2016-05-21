#ifndef VIRUSTOTAL_POLLING_VIRUSTOTALLOGIC_H
#define VIRUSTOTAL_POLLING_VIRUSTOTALLOGIC_H


#include <string>
#include "HttpClient.h"

class VirusTotalLogic
{
private:
    std::string boundary = "@@@BOUNDARY@@@";
    std::string getFilename(const std::string& filePath);
    HttpClient http;

public:
    std::string encodeData(const std::string& filePath);

    std::string getContentType();

    std::string getReport(const std::string& hash, const std::string& scan_id);

    void initializeConnection();

    void sendFile(const std::string& filePath);

    std::string parseResults(const std::string& html);

};


#endif //VIRUSTOTAL_POLLING_VIRUSTOTALLOGIC_H

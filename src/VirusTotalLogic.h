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

    std::string virusPath;
    std::string fileHash;
    std::string scan_id;

public:
    void setVirusPath(const std::string& path);

    std::string encodeData(const std::string& filePath);

    std::string getContentType();

    std::string getReport();

    void initializeConnection();

    void sendFile();

    std::string parseResults(const std::string& html);

    void saveResultsToFile(const std::string& results);

};


#endif //VIRUSTOTAL_POLLING_VIRUSTOTALLOGIC_H

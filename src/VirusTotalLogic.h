#ifndef VIRUSTOTAL_POLLING_VIRUSTOTALLOGIC_H
#define VIRUSTOTAL_POLLING_VIRUSTOTALLOGIC_H


#include <string>
#include "HttpClient.h"

class VirusTotalLogic
{
private:
    std::string encodeData(const std::string& filePath);

    void getContentFromAddress(const std::string &address, std::string &result);

    std::string getContentType();

    std::string getFilename(const std::string& filePath);

    std::string boundary = "@@@BOUNDARY@@@";
    std::string fileHash;
    HttpClient http;
    std::string scan_id;
    std::string permalink;
    std::string virusPath;

public:

    std::string getReport();

    void initializeConnection();

    std::string parseResults(const std::string& html);

    void rescan();

    void saveResultsToFile(const std::string& results);

    void sendFile();

    void setVirusPath(const std::string& path);
};


#endif //VIRUSTOTAL_POLLING_VIRUSTOTALLOGIC_H

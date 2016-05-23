#ifndef VIRUSTOTAL_POLLING_VIRUSTOTALLOGIC_H
#define VIRUSTOTAL_POLLING_VIRUSTOTALLOGIC_H


#include <string>
#include "HttpClient.h"
#include <pthread.h>
#include <stdio.h>
#include <signal.h>
#include <sys/time.h>
#include <stdlib.h>
#include <signal.h>
#include <time.h>

class VirusTotalLogic
{
private:
    std::string encodeData(const std::string& filePath);

    void getContentFromAddress(const std::string &address, std::string &result);

    std::string getContentType();

    std::string getFilename(const std::string& filePath);
    static void handleSignal(int signum);
    HttpClient http;

    std::string boundary = "@@@BOUNDARY@@@";
    std::string fileHash;
    std::string scan_id;
    std::string permalink;
    std::string virusPath;

public:

    std::string getReport();

    void initializeConnection();

    void sendFile();

    std::string parseResults(const std::string& html);

    void rescan();

    void saveResultsToFile(const std::string& results);

    void setVirusPath(const std::string& path);

    void getCyclicReport(const std::string filePath, int numberOfCycles);
};


#endif //VIRUSTOTAL_POLLING_VIRUSTOTALLOGIC_H

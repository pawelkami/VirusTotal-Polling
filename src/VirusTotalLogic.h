#ifndef VIRUSTOTAL_POLLING_VIRUSTOTALLOGIC_H
#define VIRUSTOTAL_POLLING_VIRUSTOTALLOGIC_H


#include <string>
#include "HttpClient.h"
#include <pthread.h>
#include <stdio.h>
#include <csignal>
#include <sys/time.h>
#include <stdlib.h>
#include <time.h>
#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>

class VirusTotalLogic
{
private:
    std::string encodeData(const std::string& filePath);

    void getContentFromAddress(const std::string &address, std::string &result);

    std::string getContentType();

    std::string getFilename(const std::string& filePath);

    HttpClient client;

    std::string boundary = "@@@BOUNDARY@@@";

    std::string fileHash;
    std::string scan_id;
    std::string permalink;
    std::string virusPath;
    std::string encodedFile;

    int numberOfCycles;
    int iterator;
    boost::posix_time::seconds *inter;
    boost::asio::deadline_timer *timer;
    boost::asio::io_service ioService;
    static VirusTotalLogic *instance;

    std::string prepareFileToSend(const std::string& encoded);

    std::string getReport();

    void initializeConnection();

    void sendFile(const std::string &encoded);

    std::string parseResults(const std::string& html);

    void rescan();

    void saveResultsToFile(const std::string& results);

    static void scanCycling(const boost::system::error_code& /*e*/);

    static void rescanCycling(const boost::system::error_code& /*e*/);

public:

    VirusTotalLogic() { iterator = 0; instance = this; }

    ~VirusTotalLogic();

    void setEncodedFile(const std::string &encoded);

    void setVirusPath(const std::string& path);

    void getCyclicReport(int interval, int numberOfCycles, bool toRescan);

    void setSHA256(const std::string& sha);

    void scanFile(const std::string& filepath);

    void scanFileEncoded(const std::string& encoded);

    void rescanAndSaveReport();

};


#endif //VIRUSTOTAL_POLLING_VIRUSTOTALLOGIC_H

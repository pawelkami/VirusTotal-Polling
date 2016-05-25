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
    int numberOfCycles;
    int iterator;
    boost::posix_time::seconds *inter;
    boost::asio::deadline_timer *timer;
    boost::asio::io_service ioService;
    static VirusTotalLogic *instance;

public:

    VirusTotalLogic() { iterator = 0; instance = this; }

    ~VirusTotalLogic();

    std::string getReport();

    void initializeConnection();

    void sendFile();

    std::string parseResults(const std::string& html);

    void rescan();

    void saveResultsToFile(const std::string& results);

    void setVirusPath(const std::string& path);

    void getCyclicReport(const std::string& filePath, int interval, int numberOfCycles);

    static void tick(const boost::system::error_code& /*e*/);

};


#endif //VIRUSTOTAL_POLLING_VIRUSTOTALLOGIC_H

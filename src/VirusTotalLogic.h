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
#include <memory>

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
    std::string decodedFile;

    int numberOfCycles;
    int iterator;
    std::unique_ptr<boost::posix_time::seconds> inter;
    std::unique_ptr<boost::asio::deadline_timer> timer;
    boost::asio::io_service ioService;
    static VirusTotalLogic *instance;

    std::string prepareFileToSend(const std::string& encoded);

    std::string getReport();

    void initializeConnection();

    void sendFile(const std::string &decoded);

    std::string parseResults(const std::string& html);

    void rescan();

    void saveResultsToFile(const std::string& results);

    static void rescanCycling(const boost::system::error_code& /*e*/);

public:

    VirusTotalLogic() { iterator = 0; instance = this; }

    ~VirusTotalLogic();

    void setDecodedFile(const std::string &decoded);

    void setVirusPath(const std::string& path);

    void getCyclicReport(int interval, int numberOfCycles, bool toRescan);

    void setSHA256(const std::string& sha);

    void scanFileLocal(const std::string& filepath);

    void scanFileDecoded(const std::string& decoded);

    void rescanAndSaveReport();

};


#endif //VIRUSTOTAL_POLLING_VIRUSTOTALLOGIC_H

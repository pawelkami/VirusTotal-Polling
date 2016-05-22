#ifndef VIRUSTOTAL_POLLING_LOGGER_H
#define VIRUSTOTAL_POLLING_LOGGER_H

#include <string>
#include <fstream>
#include "Utils.h"

#define LOGFILENAME "log.txt"
#define LOGGER Logger::getInstance()

#define LOG_ERROR(Message_) LOGGER.log(ERROR, Message_, __FUNCTION__)
#define LOG_INFO(Message_) LOGGER.log(INFO, Message_, __FUNCTION__)
#define LOG_WARNING(Message_) LOGGER.log(WARNING, Message_, __FUNCTION__)
#define LOG_DEBUG(Message_) LOGGER.log(DEBUG, Message_, __FUNCTION__)


enum Level
{
    ERROR,
    INFO,
    WARNING,
    DEBUG
};

class Logger
{
private:
    Logger();

    std::ofstream outFile;

    void openLogFile();
public:
    static Logger& getInstance();

    ~Logger();

    void log(Level level, const std::string& message, char const* function );

};


#endif //VIRUSTOTAL_POLLING_LOGGER_H

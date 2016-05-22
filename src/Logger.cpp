#include "Logger.h"
#include <chrono>
#include <ctime>
#include "Configuration.h"

Logger &Logger::getInstance()
{
    static Logger log;
    return log;
}

Logger::Logger()
{
}

Logger::~Logger()
{
    if(outFile.is_open())
        outFile.close();
}

void Logger::log(Level level, const std::string &message, char const* function)
{
    openLogFile();
    std::string lvl;
    switch(level)
    {
        case ERROR:
            lvl = " ERROR: ";
            break;

        case WARNING:
            lvl = " WARNING: ";
            break;

        case INFO:
            lvl = " INFO: ";
            break;

        case DEBUG:
            lvl = " DEBUG: ";
            break;
    }

    outFile << currentDateTime() << lvl << " " << function << "() " << message << '\n';
    outFile.close();
}

void Logger::openLogFile()
{
    if(CONFIG.has("logfile_path"))
    {
        outFile.open(CONFIG.getValue("logfile_path"), std::ios::out | std::ios::app);
    }
    else
        outFile.open(LOGFILENAME, std::ios::out | std::ios::app);
}










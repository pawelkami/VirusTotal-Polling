#include "Logger.h"
#include <chrono>
#include <ctime>

Logger &Logger::getInstance()
{
    static Logger log;
    return log;
}

Logger::Logger()
{
    outFile.open(LOGFILENAME, std::ios::out | std::ios::app);
}

Logger::~Logger()
{
    if(outFile.is_open())
        outFile.close();
}

void Logger::log(Level level, const std::string &message, char const* function)
{
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

    time_t now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    std::string time(std::ctime(&now));
    time = time.substr(0, time.size()-1);
    outFile << time << lvl << " " << function << "() " << message << '\n';

}








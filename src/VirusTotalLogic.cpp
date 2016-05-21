#include <sys/stat.h>
#include "VirusTotalLogic.h"
#include "Parser.h"
#include "ResultsAnalyzer.h"

void VirusTotalLogic::initializeConnection()
{
    http.init();
}

void VirusTotalLogic::sendData(const std::string &data)
{

}

std::string VirusTotalLogic::parseResults(const std::string &html)
{
    Parser htmlParser = Parser(html);
    htmlParser.parse();
    ResultsAnalyzer analyzer = ResultsAnalyzer(htmlParser.getRoot());
    std::stringstream ss;
    std::string resultConf = CONFIG.getValue("results");

    if(resultConf.find("all") != std::string::npos || resultConf.empty())
    {
        ss << analyzer.getBasicInfo() << std::endl << analyzer.getAntyvirList();
        return ss.str();
    }

    if(resultConf.find("sha") != std::string::npos)
    {
        ss << analyzer.getSHA() << std::endl;
    }

    if(resultConf.find("filename") != std::string::npos)
    {
        ss << analyzer.getFilename() << std::endl;
    }

    if(resultConf.find("ratio") != std::string::npos)
    {
        ss << analyzer.getDetectionRatio() << std::endl;
    }

    if(resultConf.find("date") != std::string::npos)
    {
        ss << analyzer.getAnalysisDate() << std::endl;
    }

    if(resultConf.find("nolist") == std::string::npos)
    {
        ss << analyzer.getAntyvirList();
    }


    return ss.str();
}

void VirusTotalLogic::saveResultsToFile(const std::string &results)
{
    std::string resultsPath = CONFIG.getValue("results_path");
    if(!resultsPath.empty() && resultsPath[resultsPath.size()-1] != '/')
    {
        resultsPath += '/';
    }

    if(!resultsPath.empty())
        mkdir(resultsPath.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);

    std::string filename =  resultsPath + virusPath.substr(virusPath.find_last_of('/') + 1, virusPath.size());

    filename += currentDateTime() + ".txt";

    std::ofstream fout;
    fout.open(filename);

    if(!fout.is_open())
    {
        LOG_ERROR("Failed opening file " + filename);
        return;
    }

    fout << results;

    fout.close();
}

void VirusTotalLogic::setVirusPath(const std::string &path)
{
    virusPath = path;
}










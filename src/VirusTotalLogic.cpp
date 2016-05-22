
#include <sys/stat.h>
#include <fstream>
#include <vector>
#include "VirusTotalLogic.h"
#include "HttpRequest.h"
#include "HttpResponse.h"
#include "Parser.h"
#include "ResultsAnalyzer.h"


void VirusTotalLogic::initializeConnection()
{
    http.init();
}

std::string VirusTotalLogic::encodeData(const std::string &filePath)
{
    std::ifstream is;
    is.open(filePath, std::ios::binary | std::ios::out);
    if (is.fail())
    {
        throw std::runtime_error("Could not open " + filePath);
    }
    std::stringstream buffer;
    buffer << is.rdbuf();
    is.close();

    std::string fileData = buffer.str();

    std::string newLine = "\r\n";

    std::vector<std::string> bodyParts;

    // Add apikey.
    bodyParts.push_back("--" + this->boundary);
    bodyParts.push_back("Content-Disposition: form-data; name=\"apikey\"");
    bodyParts.push_back("");
    bodyParts.push_back(CONFIG.getValue("apikey"));

    // Add file.
    bodyParts.push_back("--" + this->boundary);
    bodyParts.push_back("Content-Disposition: form-data; name=\"file\"; filename=\"" +
                        getFilename(filePath) + "\"");
    bodyParts.push_back("Content-Type: application/octet-stream");
    bodyParts.push_back("");
    bodyParts.push_back(fileData);
    bodyParts.push_back("--" + this->boundary + "--");

    std::string body = "";

    // Create body.
    for(auto it = bodyParts.begin(); it != bodyParts.end(); ++it)
    {
        body += it->data() + newLine;
    }
    return body;
}

std::string VirusTotalLogic::getContentType()
{
    return "multipart/form-data; boundary=\"" + this->boundary +"\"";
}

std::string VirusTotalLogic::getFilename(const std::string& filePath)
{
    unsigned long slashIndex = filePath.find_last_of("/");
    return filePath.substr(slashIndex + 1, std::string::npos);
}

std::string VirusTotalLogic::getReport()
{
    HttpRequest request;
    request.putRequest(POST, CONFIG.getValue("report_url") + "?resource=" + fileHash + "&apikey=" + CONFIG.getValue("apikey") +
            "&scan_id=" + scan_id);
    request.putHeader("content-length", "0");

    http.sendMsg(request);
    HttpResponse response = http.receiveResponse();

    // Teraz trzeba chyba sprawdzić response_code w odpowiedzi i w zależności od jego wartości, albo dalej odpytywać
    // ten sam url, albo wyciągnąć permalink i pobrać całą stronę z wynikami skanowań.

    return "";
}

void VirusTotalLogic::sendFile()
{
    std::string body = encodeData(virusPath);
    HttpRequest request;
    request.putRequest(POST, CONFIG.getValue("scan_url"));
    request.putHeader("content-type", getContentType());
    request.putHeader("content-length", std::to_string(body.size()));
    request.putBody(body);

    http.sendMsg(request);
    HttpResponse response = http.receiveResponse();

    std::string responseBody = response.getBody();
    int jsonStart = responseBody.find_first_of("{");
    int jsonEnd = responseBody.find_last_of("}");

    JsonObject json;
    json.init(responseBody.substr(jsonStart, jsonEnd - jsonStart + 1));

    fileHash = json.getValue("md5");
    scan_id = json.getValue("scan_id");
    LOG_INFO("Received md5 = " + fileHash + ", scan_id = " + scan_id);
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










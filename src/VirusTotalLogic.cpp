#include <sys/stat.h>
#include <unistd.h>
#include <fstream>
#include <vector>
#include "VirusTotalLogic.h"
#include "src/exception/RequestException.h"
#include "src/exception/FileException.h"
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
        LOG_ERROR("Failed opening file " + filePath);
        throw FileException("Failed opening file" + filePath);
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

    while(true)
    {
        http.sendMsg(request);
        HttpResponse response = http.receiveResponse();

        std::string responseBody = response.getBody();

        size_t jsonStart = responseBody.find_first_of("{");
        size_t jsonEnd = responseBody.find_last_of("}");

        if (jsonStart == std::string::npos || jsonEnd == std::string::npos)
        {
            LOG_ERROR("Invalid response body");
            throw RequestException("Invalid response body");
        }

        JsonObject json;
        json.init(responseBody.substr(jsonStart, jsonEnd - jsonStart + 1));
        std::string responseCode = json.getValue("response_code");
        if (responseCode == "1")
        {
            permalink = json.getValue("permalink");
            break;
        }
        else
        {
            sleep(15);
        }
    }

    std::string html;

    getContentFromAddress(permalink, html);

    return html;
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

    if (response.getResponseCode()[0] != '2')
    {
        LOG_ERROR("Response code " + response.getResponseCode() + " after sending file");
        throw RequestException(response.getResponseCode());
    }

    std::string responseBody = response.getBody();
    size_t jsonStart = responseBody.find_first_of("{");
    size_t jsonEnd = responseBody.find_last_of("}");

    if (jsonStart == std::string::npos || jsonEnd == std::string::npos)
    {
        LOG_ERROR("Invalid response body");
        throw RequestException("Invalid response body");
    }

    JsonObject json;
    json.init(responseBody.substr(jsonStart, jsonEnd - jsonStart + 1));

    fileHash = json.getValue("sha256");
    scan_id = json.getValue("scan_id");
    permalink = json.getValue("permalink");
    LOG_INFO("Received sha256 = " + fileHash + ", scan_id = " + scan_id);
}

void VirusTotalLogic::rescan()
{
    HttpRequest request;
    request.putRequest(POST, CONFIG.getValue("rescan_url") + "?resource=" + fileHash + "&apikey=" + CONFIG.getValue("apikey"));
    request.putHeader("content-length", "0");

    http.sendMsg(request);
    HttpResponse response = http.receiveResponse();

    std::string responseBody = response.getBody();

    size_t jsonStart = responseBody.find_first_of("{");
    size_t jsonEnd = responseBody.find_last_of("}");

    if (jsonStart == std::string::npos || jsonEnd == std::string::npos)
    {
        LOG_ERROR("Invalid response body");
        throw RequestException("Invalid response body");
    }

    JsonObject json;
    json.init(responseBody.substr(jsonStart, jsonEnd - jsonStart + 1));
    scan_id = json.getValue("scan_id");
    permalink = json.getValue("permalink");
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
        if(mkdir(resultsPath.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH) == -1)
        {
            LOG_ERROR("Failed creating directory " + resultsPath + ", error: " + std::string(strerror(errno)));
            resultsPath = "";
        }

    std::string filename =  resultsPath + virusPath.substr(virusPath.find_last_of('/') + 1, virusPath.size());

    filename += currentDateTime() + ".txt";

    std::ofstream fout;
    fout.open(filename);

    if(!fout.is_open())
    {
        LOG_ERROR("Failed opening file " + filename);
        throw FileException("Failed opening file " + filename);
        return;
    }

    fout << results;

    fout.close();
    LOG_INFO("Saved results");
}

void VirusTotalLogic::setVirusPath(const std::string &path)
{
    virusPath = path;
}

void VirusTotalLogic::getContentFromAddress(const std::string &address, std::string &result)
{
    size_t pos = 0;
    std::string relativePath;
    if ((pos = address.find(CONFIG.getValue("host"))) != std::string::npos)
    {
        relativePath = address.substr(pos+CONFIG.getValue("host").length(),std::string::npos);
        LOG_DEBUG("relativePath = " + relativePath);
    }

    else
    {
        LOG_ERROR("Wrong address given = " + address);
        return;
    }

    HttpRequest req;
    req.putRequest(HttpMethod::GET, relativePath);
    req.putHeader("host", CONFIG.getValue("host"));
    http.sendMsg(req);
    HttpResponse r = http.receiveResponse();
    LOG_DEBUG(r.getResponseCode() + ", " + r.getHeader("Location"));
    if (r.getResponseCode() == "301")
        getContentFromAddress(r.getHeader("Location"), result);
    else if (r.getResponseCode() == "200")
        result = r.getBody();
    else
    {
        throw RequestException(r.getResponseCode());
    }
}

void VirusTotalLogic::getCyclicReport(const std::string filePath, int numberOfCycles)
{
    struct itimerval timer;
    /* Initial timeout value */
    timer.it_value.tv_sec = 0;
    timer.it_value.tv_usec = 250000;

    /* We want a repetitive timer */
    timer.it_interval.tv_sec = 60; //60 * std::stoi(CONFIG.getValue("polling_interval_minutes_default"));
    timer.it_interval.tv_usec = 0;

    signal(SIGALRM, &handleSignal);
    setitimer(ITIMER_REAL, &timer, NULL);
}

void VirusTotalLogic::handleSignal(int signum)
{
    std::cout << "Dupa" << std::endl;
}





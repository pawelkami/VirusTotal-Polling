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

VirusTotalLogic *VirusTotalLogic::instance;

void VirusTotalLogic::initializeConnection()
{
    client.init();
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

    return fileData;
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

VirusTotalLogic::~VirusTotalLogic()
{
    delete(timer);
}


std::string VirusTotalLogic::getReport()
{
    HttpRequest request;
    request.putRequest(POST, CONFIG.getValue("report_url") + "?resource=" + fileHash + "&apikey=" + CONFIG.getValue("apikey") +
            "&scan_id=" + scan_id);
    request.putHeader("content-length", "0");

    while(true)
    {
        client.sendMsg(request.getRequest());
        HttpResponse response = client.receiveResponse();

        std::string responseBody = response.getBody();

        if (response.getResponseCode()[0] != '2')
        {
            LOG_ERROR("Code " + response.getResponseCode() + " while trying to get report URL");
            throw RequestException(response.getResponseCode());
        }

        JsonObject json;
        json.init(responseBody);
        std::string responseCode = json.getValue("response_code");
        if (responseCode == "1")
        {
            permalink = json.getValue("permalink");
            break;
        }
        else
        {
            LOG_INFO("Scan not yet completed. Waiting 15 seconds.");
            sleep(15);
        }
    }

    LOG_INFO("Scan completed");

    std::string html;

    getContentFromAddress(permalink, html);

    return html;
}

void VirusTotalLogic::sendFile(const std::string& encoded)
{
    std::string body = prepareFileToSend(encoded);
    HttpRequest request;
    request.putRequest(POST, CONFIG.getValue("scan_url"));
    request.putHeader("content-type", getContentType());
    request.putHeader("content-length", std::to_string(body.size()));
    request.putBody(body);

    client.sendMsg(request.getRequest());
    HttpResponse response = client.receiveResponse();

    if (response.getResponseCode()[0] != '2')
    {
        LOG_ERROR("Response code " + response.getResponseCode() + " after sending file");
        throw RequestException(response.getResponseCode());
    }

    std::string responseBody = response.getBody();

    JsonObject json;
    json.init(responseBody);

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

    client.sendMsg(request.getRequest());
    HttpResponse response = client.receiveResponse();

    if (response.getResponseCode()[0] != '2')
    {
        LOG_ERROR("Response code " + response.getResponseCode() + " after sending rescan request");
        throw RequestException(response.getResponseCode());
    }

    std::string responseBody = response.getBody();

    JsonObject json;
    json.init(responseBody);
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
    struct stat sb;


    if(!resultsPath.empty())
        if (!(stat(resultsPath.c_str(), &sb) == 0 && S_ISDIR(sb.st_mode)))
        {
            if(mkdir(resultsPath.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH) == -1)
            {
                LOG_WARNING("Failed creating directory " + resultsPath + ", error: " + std::string(strerror(errno)));
                resultsPath = "";
            }
        }
    std::string filename;
    if(!virusPath.empty())
        filename =  resultsPath + virusPath.substr(virusPath.find_last_of('/') + 1);
    else
        filename = fileHash;

    filename += currentDateTime() + ".txt";

    std::ofstream fout;
    fout.open(filename);

    if(!fout.is_open())
    {
        LOG_ERROR("Failed opening file " + filename);
        throw FileException("Failed opening file " + filename);
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
    client.sendMsg(req.getRequest());
    HttpResponse r = client.receiveResponse();
    LOG_DEBUG(r.getResponseCode() + ", " + r.getHeader("Location"));
    if (r.getResponseCode() == "301")
        getContentFromAddress(r.getHeader("Location"), result);
    else if (r.getResponseCode() == "200")
    {
        result = r.getBody();
        LOG_INFO("Report downloaded");
    }
    else
    {
        throw RequestException(r.getResponseCode());
    }
}

void VirusTotalLogic::getCyclicReport(const std::string& filePath, int interval, int numberOfCycles)
{
    this->numberOfCycles = numberOfCycles;
    inter = new boost::posix_time::seconds(1);//interval * 60);
    timer = new boost::asio::deadline_timer(ioService, *inter);
    timer->async_wait(tick);
    ioService.run();
}

void VirusTotalLogic::tick(const boost::system::error_code& /*e*/)
{
    std::cout << "tick" << std::endl;
//    instance->initializeConnection();
//    instance->rescan();
//    std::string html = instance->getReport();
//    std::string results = instance->parseResults(html);
//    instance->saveResultsToFile(results);
    if(++(instance->iterator) != instance->numberOfCycles)
    {
        instance->timer->expires_at(instance->timer->expires_at() + *(instance->inter));
        instance->timer->async_wait(boost::bind(VirusTotalLogic::tick, boost::asio::placeholders::error));
    }
}

void VirusTotalLogic::setSHA256(const std::string &sha)
{
    this->fileHash = sha;
}

void VirusTotalLogic::scanFile(const std::string &filePath)
{
    initializeConnection();
    setVirusPath(filePath);
    sendFile(encodeData(filePath));
    std::string html = getReport();
    std::string results = parseResults(html);
    saveResultsToFile(results);
}

void VirusTotalLogic::scanFileEncoded(const std::string &encoded)
{
    initializeConnection();
    sendFile(encoded);
    std::string html = getReport();
    std::string results = parseResults(html);
    saveResultsToFile(results);
}

std::string VirusTotalLogic::prepareFileToSend(const std::string &encoded)
{
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
                        getFilename(this->virusPath) + "\"");
    bodyParts.push_back("Content-Type: application/octet-stream");
    bodyParts.push_back("");
    bodyParts.push_back(encoded);
    bodyParts.push_back("--" + this->boundary + "--");

    std::string body = "";

    // Create body.
    for(auto it = bodyParts.begin(); it != bodyParts.end(); ++it)
    {
        body += it->data() + newLine;
    }
    return body;
}

void VirusTotalLogic::rescanAndSaveReport()
{
    initializeConnection();
    rescan();
    std::string html = getReport();
    std::string results = parseResults(html);
    saveResultsToFile(results);

}










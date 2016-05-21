#include <fstream>
#include <vector>
#include "VirusTotalLogic.h"
#include "HttpRequest.h"


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

std::string VirusTotalLogic::getReport(const std::string& hash, const std::string& scan_id)
{
    HttpRequest request;
    request.putRequest(POST, CONFIG.getValue("report_url") + "?resource=" + hash + "&apikey=" + CONFIG.getValue("apikey") +
            "&scan_id=" + scan_id);
    request.putHeader("content-length", "0");

    http.send(request);
    std::string response = http.receiveResponse();

    // Teraz trzeba chyba sprawdzić response_code w odpowiedzi i w zależności od jego wartości, albo dalej odpytywać
    // ten sam url, albo wyciągnąć permalink i pobrać całą stronę z wynikami skanowań.

    return "";
}

void VirusTotalLogic::sendFile(const std::string &filePath)
{
    std::string body = encodeData(filePath);
    HttpRequest request;
    request.putRequest(POST, CONFIG.getValue("scan_url"));
    request.putHeader("content-type", getContentType());
    request.putHeader("content-length", std::to_string(body.size()));
    request.putBody(body);

    http.send(request);
    std::string response = http.receiveResponse();

    // tutaj trzeba wyciągnąć scan_id i jeden z hashy (np. md5)
}

std::string VirusTotalLogic::parseResults(const std::string &html)
{
    return "";
}






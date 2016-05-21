#include <fstream>
#include <vector>
#include "VirusTotalLogic.h"


void VirusTotalLogic::initializeConnection()
{
    boundary = "@@@BOUNDARY@@@";
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
    bodyParts.push_back("-- " + CONFIG.getValue("apikey") + " --");

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

void VirusTotalLogic::sendData(const std::string &data)
{

}

std::string VirusTotalLogic::parseResults(const std::string &html)
{
    return "";
}






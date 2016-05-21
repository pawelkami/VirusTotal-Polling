#include "Configuration.h"
#include "Logger.h"
#include "HttpClient.h"
#include "VirusTotalLogic.h"

using namespace std;

int main(int argc, char** argv)
{
    HttpClient http;
    //http.init();

    std::string reqStr = "POST /cgi-bin/process.cgi HTTP/1.1\n"
            "User-Agent: Mozilla/4.0 (compatible; MSIE5.01; Windows NT)\n"
            "Host: www.tutorialspoint.com\n"
            "Content-Type: application/x-www-form-urlencoded\n"
            "Content-Length: length\n"
            "Accept-Language: en-us\n"
            "Accept-Encoding: gzip, deflate\n"
            "Connection: Keep-Alive\n"
            "\n"
            "licenseID=string&content=string&/paramsXML=string";
    HttpRequest request(reqStr);

    std::string body = request.getBody();
    LOG_DEBUG("aaa");

    VirusTotalLogic vt;

    vt.setVirusPath("/home/kamienny/Github/VirusTotal-Polling/aaa.txt");
    vt.saveResultsToFile("aaaaaaaaa");
	return 0;
}
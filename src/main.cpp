#include "Configuration.h"
#include "Logger.h"
#include "HttpClient.h"

using namespace std;

int main(int argc, char** argv)
{
    HttpClient http;

    HttpRequest request;
    request.putRequest(HttpMethod::GET, "/");
    request.putHeader("Host", "www.virustotal.com");
    request.putHeader("Accept", "*/*");
    request.putHeader("Connection", "Keep-Alive");

    http.init();
    http.sendMsg(request);
    std::cout << http.receiveResponse();

	return 0;
}
#include "Configuration.h"
#include "Logger.h"
#include "HttpClient.h"

using namespace std;

int main(int argc, char** argv)
{
    HttpClient http;
    HttpRequest request;
    request.putRequest(HttpMethod::GET, "virustotal.com/lucek.html");
    http.init();
    http.sendMsg(request);
    std::cout << http.receiveResponse();

	return 0;
}
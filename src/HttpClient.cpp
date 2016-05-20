#include <netdb.h>
#include <cstring>
#include <unistd.h>
#include "HttpClient.h"
#include "HttpRequest.h"

void HttpClient::init()
{
    struct sockaddr_in addr;
    struct hostent* server;

    // create socket
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if(sock < 0)
    {
        LOG_ERROR("creating socket failed");
        return;
    }

    // lookup ip address
    std::string hostname = CONFIG.getValue("host");
    if(hostname.empty())
    {
        LOG_ERROR("No 'host' in configuration file");
        return;
    }

    server = gethostbyname(CONFIG.getValue("host").c_str());
    if(server == nullptr)
    {
        LOG_ERROR("No such host");
        return;
    }



    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = 0;
    memcpy(&addr.sin_addr.s_addr, server->h_addr, server->h_length);


    if(connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0 )
    {
        LOG_ERROR("Connection failed");
        return;
    }

    close(sock);

}

HttpClient::HttpClient()
{

}

HttpClient::~HttpClient()
{

}

void HttpClient::send(const HttpRequest &request) {

}

std::string HttpClient::receiveResponse()
{
    return "";
}










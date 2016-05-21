#include <netdb.h>
#include <cstring>
#include <unistd.h>
#include "HttpClient.h"
#include "HttpRequest.h"

void HttpClient::init()
{
    LOG_DEBUG("");
    struct sockaddr_in addr;
    struct hostent* server;

    // create socket
    sock = socket(AF_INET, SOCK_STREAM, 0);
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
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(80);
    inet_aton(server->h_addr,&addr.sin_addr);


    if(connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0 )
    {
        LOG_ERROR("Connection failed");
        close(sock);
        return;
    }

}

HttpClient::HttpClient()
{

}

HttpClient::~HttpClient()
{
    close(sock);
}

void HttpClient::sendMsg(const HttpRequest &request)
{
    auto msg = request.getRequest();
    if(send(sock, msg.c_str(), msg.length(), 0) != (int)msg.length())
    {
        LOG_ERROR("Error sending request.");
        return;
    }
}

std::string HttpClient::receiveResponse()
{
    std::string answer;
    char answ[1024];
    memset(answ, 0, sizeof(answ));
    while(recv(sock,answ,sizeof(answ),0) > 0)
        answer += std::string(answ);
    return answer;
}










#include "HttpServer.h"
#include "JsonObject.h"
#include "Logger.h"
#include "VirusTotalLogic.h"
#include <sys/wait.h>
#include <signal.h>

HttpServer::HttpServer()
{
    signal(SIGCHLD, &sigchldHandler);
    isSSL = false;
}

void HttpServer::handleConnection(int newSocket)
{
    std::string clientMessage = receiveMsg(newSocket);
    HttpRequest request(clientMessage);

    std::cout << clientMessage << std::endl;

    std::string fileBody = "";
    if(request.getHeader("Content-Type").find("application/octet-stream") != std::string::npos)
    {
        LOG_DEBUG("Content-Type == application/octet-stream");
        sendMsg("HTTP/1.1 201 Created\r\n\r\n", newSocket);
        fileBody = request.getBody();
        clientMessage = receiveMsg(newSocket);
        request = HttpRequest(clientMessage);
        sendMsg("HTTP/1.1 200 OK\r\n\r\n", newSocket);
    }

    if(!handleMessage(request.getBody(), fileBody))
    {
        LOG_ERROR("Received bad Http Request");
        sendMsg("HTTP/1.1 400 Bad Request\r\n\r\n", newSocket);
    }

    sendMsg("HTTP/1.1 200 OK\r\n\r\n", newSocket);

    return;
}

void HttpServer::init()
{
    sock = socket(AF_INET , SOCK_STREAM , 0);
    if (sock == -1)
    {
        printf("Could not create socket");
    }
    sockaddr_in server;
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;

    if(!CONFIG.has("port_server"))
    {
        LOG_ERROR("No 'port_server' key in configuration file");
        throw std::runtime_error("No 'port_server' key in configuration file");
    }

    int port = std::stoi(CONFIG.getValue("port_server"));
    server.sin_port = htons(port);

    if( bind(sock,(struct sockaddr *)&server , sizeof(server)) < 0)
    {
        puts("bind failed");
        LOG_ERROR("bind to port = " + std::to_string(port) + " failed");
        return;
    }
    puts("bind done");
    LOG_INFO("bind done");
}

void HttpServer::startServer()
{
    init();
    listen(sock, 3);

    //Accept and incoming connection
    puts("Waiting for incoming connections...");
    int c = sizeof(struct sockaddr_in);
    int newSocket;
    sockaddr_in client;

    while(true)
    {
        if( (newSocket = accept(sock, (struct sockaddr *)&client, (socklen_t*)&c)) )
        {
            puts("Connection accepted");
            LOG_INFO("Connection accepted");

            handleConnection(newSocket);
        }

        if (newSocket<0)
        {
            perror("accept failed");
            LOG_INFO("accept failed");
        }
    }
}

HttpServer::~HttpServer()
{
    close(sock);
}

bool HttpServer::handleMessage(const std::string &message, const std::string& fileBody)
{
    JsonObject json;
    json.init(message);
    if(!json.has("type"))
    {
        LOG_ERROR("Received JSON does not contain 'type'");
        return false;
    }

    std::string type = json.getValue("type");

    // nowy proces do obslugi polaczenia
    pid_t pid;
    if((pid = fork()) == 0)
    {
        VirusTotalLogic vtl;

        if(type == "rescan")
        {
            if(!json.getValue("sha256").empty())
            {
                vtl.setSHA256(json.getValue("sha256"));
                if(json.getValue("cycling") == "yes")
                {
                    vtl.getCyclicReport(atoi(json.getValue("interval").c_str()), atoi(json.getValue("numberOfCycles").c_str()), true);
                }
                else
                {
                    vtl.rescanAndSaveReport();
                }
            }
            else
            {
                LOG_ERROR("No sha256 in message");
            }
        }
        else if(type == "send")
        {
            if(fileBody.empty())
            {
                vtl.setVirusPath(json.getValue("filename"));
                vtl.setEncodedFile(fileBody);
                if(json.getValue("cycling") == "yes")
                {
                    vtl.getCyclicReport(atoi(json.getValue("interval").c_str()), atoi(json.getValue("numberOfCycles").c_str()), false);
                }
                else
                {
                    vtl.scanFileEncoded(fileBody);
                }
            }
            else
            {
                LOG_ERROR("No body of file in message");
            }
        }

        exit(0);
    }
    LOG_INFO("New process, pid = " + std::to_string(pid));
    return true;

}

HttpServer &HttpServer::getInstance()
{
    static HttpServer server;
    return server;
}

void HttpServer::sigchldHandler(int sig)
{
    pid_t pid;
    pid = wait(NULL);
    LOG_INFO("Process has ended. pid = " + std::to_string(pid));
}








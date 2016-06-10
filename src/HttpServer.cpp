#include "HttpServer.h"
#include "JsonObject.h"
#include "Logger.h"
#include "VirusTotalLogic.h"
#include <sys/wait.h>
#include <signal.h>
#include "Utils.h"

HttpServer::HttpServer()
{
    signal(SIGCHLD, &sigchldHandler);
    isSSL = false;
}

void HttpServer::handleConnection(int newSocket)
{
    std::string clientMessage = receiveMsg(newSocket);
    HttpRequest request(clientMessage);
    std::string responseBody;
    if(!handleMessage(request.getBody(), responseBody))
    {
        LOG_ERROR("Received bad Http Request");
        sendMsg("HTTP/1.1 400 Bad Request\r\n\r\n", newSocket);
    }

    size_t bodyLength = responseBody.length();
    if(bodyLength)
    {
        LOG_INFO("OK, Sending HTTP/1.1 200 OK with Content-Length: " + std::to_string(bodyLength));
        sendMsg("HTTP/1.1 200 OK\r\n"
                "Content-Length: " + std::to_string(bodyLength) +
                "\r\n\r\n" +
                responseBody +
                "\r\n",
                newSocket);
    }
    else
    {
        LOG_INFO("OK, Sending HTTP/1.1 200 OK");

        sendMsg("HTTP/1.1 200 OK\r\n\r\n", newSocket);
    }
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
        throw std::runtime_error("bind failed");
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

            pid_t pid;
            if((pid = fork()) == 0)
            {
                handleConnection(newSocket);
                exit(0);
            }
            else
            {
                LOG_INFO("New process pid = " + std::to_string(pid));
            }
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

bool HttpServer::handleMessage(const std::string &message, std::string &responseBody)
{
    JsonObject json;
    json.init(message);
    if(!json.has("type"))
    {
        LOG_ERROR("Received JSON does not contain 'type'");
        return false;
    }

    std::string type = json.getValue("type");

    VirusTotalLogic vtl;

    if(json.has("result_conf"))
    {
        LOG_DEBUG("Incoming result_conf " + json.getValue("result_conf"));
        vtl.setResultConf(json.getValue("result_conf"));
    }

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
        if(json.has("file"))
        {
            vtl.setVirusPath(json.getValue("filename"));
            vtl.setDecodedFile(base64_decode(json.getValue("file")));
            if(json.getValue("cycling") == "yes")
            {
                vtl.getCyclicReport(atoi(json.getValue("interval").c_str()), atoi(json.getValue("numberOfCycles").c_str()), false);
            }
            else
            {
                vtl.scanFileDecoded(base64_decode(json.getValue("file")));
            }
        }
        else
        {
            LOG_ERROR("No body of file in message");
        }
    }
    else if(type == "get_results")
    {
        LOG_INFO("");
        responseBody = vtl.getResult(json.getValue("sha256"));
    }
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








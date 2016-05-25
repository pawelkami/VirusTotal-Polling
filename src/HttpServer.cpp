#include "HttpServer.h"
#include "JsonObject.h"
#include "Logger.h"
#include "VirusTotalLogic.h"

HttpServer::HttpServer()
{

}

void* HttpServer::connectionHandler(void *sock)
{
    int socketClient = *(int*)sock;
    HttpServer server = HttpServer::getInstance();
    //Send some messages to the client
    char* message = "Greetings! I am your connection handler\n";
    server.sendMsg(message, socketClient);

    message = "Now type something and i shall repeat what you type \n";
    HttpServer::getInstance().sendMsg(message, socketClient);

    std::string clientMessage = server.receiveMsg(socketClient);
    HttpRequest request(clientMessage);

    std::cout << clientMessage << std::endl;
    if(!server.handleMessage(request.getBody()))
    {
        LOG_ERROR("Received bad Http Request");
        // TODO powiedziec o bledzie klientowi
    }

    // TODO odpowiedziec klientowi

    return 0;
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
    server.sin_port = htons( 8888 );    // port do wyedytowania TODO

    if( bind(sock,(struct sockaddr *)&server , sizeof(server)) < 0)
    {
        puts("bind failed");
        return;
    }
    puts("bind done");
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
    while( (newSocket = accept(sock, (struct sockaddr *)&client, (socklen_t*)&c)) )
    {
        puts("Connection accepted");

        //Reply to the client
        reply(newSocket);
    }

    if (newSocket<0)
    {
        perror("accept failed");
        return;
    }
}

void HttpServer::reply(int newSocket)
{
    char *message = "Hello Client , I have received your connection. And now I will assign a handler for you\n";
    HttpServer::getInstance().sendMsg(message, newSocket);

    pthread_t sniffer_thread;

    if( pthread_create( &sniffer_thread , NULL ,  HttpServer::connectionHandler , &newSocket) < 0)
    {
        perror("could not create thread");
        return;
    }

    puts("Handler assigned");
}

HttpServer::~HttpServer()
{
    close(sock);
}

bool HttpServer::handleMessage(const std::string &message)
{
    JsonObject json;

    json.init(message);
    if(!json.has("type"))
    {
        LOG_ERROR("Received JSON does not contain 'type'");
        return false; // TODO throw
    }

    std::string type = json.getValue("type");

    VirusTotalLogic vtl;
    if(type == "rescan")
    {
        // TODO obsluga zwykla i cykliczne
    }
    else if(type == "send")
    {
        // TODO obsluga zwykla i cykliczna
    }

    return true;

}

HttpServer &HttpServer::getInstance()
{
    static HttpServer server;
    return server;
}






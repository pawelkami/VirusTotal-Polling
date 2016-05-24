#include "HttpServer.h"
#include "JsonObject.h"
#include "Logger.h"
#include "VirusTotalLogic.h"

HttpServer::HttpServer()
{

}

void* HttpServer::connectionHandler(void *socket_desc)
{
    //Get the socket descriptor
    int sock = *(int*)socket_desc;
    int read_size;
    char *message , clientMessage[2000];

    //Send some messages to the client
    message = "Greetings! I am your connection handler\n";
    write(sock , message , strlen(message));

    message = "Now type something and i shall repeat what you type \n";
    write(sock , message , strlen(message));

    //Receive a message from client
    while( (read_size = recv(sock , clientMessage , 2000 , 0)) > 0 )
    {
        //Send the message back to client
        write(sock , clientMessage , strlen(clientMessage));
    }

    if(read_size == 0)
    {
        puts("Client disconnected");
        fflush(stdout);
    }
    else if(read_size == -1)
    {
        perror("recv failed");
    }

    handleMessage(clientMessage);

    return 0;
}

void HttpServer::initialize()
{
    socketListen = socket(AF_INET , SOCK_STREAM , 0);
    if (socketListen == -1)
    {
        printf("Could not create socket");
    }

    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons( 8888 );    // port do wyedytowania TODO

    if( bind(socketListen,(struct sockaddr *)&server , sizeof(server)) < 0)
    {
        puts("bind failed");
        return;
    }
    puts("bind done");
}

void HttpServer::startServer()
{
    initialize();
    listen(socketListen , 3);

    //Accept and incoming connection
    puts("Waiting for incoming connections...");
    int c = sizeof(struct sockaddr_in);
    int newSocket;
    while( (newSocket = accept(socketListen, (struct sockaddr *)&client, (socklen_t*)&c)) )
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
    write(newSocket , message , strlen(message));

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
    close(socketListen);
}

void HttpServer::handleMessage(const std::string &message)
{
    JsonObject json;
    json.init(message);
    if(!json.has("type"))
    {
        LOG_ERROR("Received JSON does not contain 'type'");
        return; // TODO throw
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

}




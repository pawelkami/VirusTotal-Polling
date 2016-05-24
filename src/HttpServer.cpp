#include "HttpServer.h"

HttpServer::HttpServer()
{

}

void* HttpServer::connection_handler(void *socket_desc)
{
    //Get the socket descriptor
    int sock = *(int*)socket_desc;
    int read_size;
    char *message , client_message[2000];

    //Send some messages to the client
    message = "Greetings! I am your connection handler\n";
    write(sock , message , strlen(message));

    message = "Now type something and i shall repeat what you type \n";
    write(sock , message , strlen(message));

    //Receive a message from client
    while( (read_size = recv(sock , client_message , 2000 , 0)) > 0 )
    {
        //Send the message back to client
        write(sock , client_message , strlen(client_message));
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

    //Free the socket pointer
    free(socket_desc);

    return 0;
}

void HttpServer::initialize()
{
    socket_desc = socket(AF_INET , SOCK_STREAM , 0);
    if (socket_desc == -1)
    {
        printf("Could not create socket");
    }

    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons( 8888 );    // port do wyedytowania

    if( bind(socket_desc,(struct sockaddr *)&server , sizeof(server)) < 0)
    {
        puts("bind failed");
        return;
    }
    puts("bind done");
}

void HttpServer::startServer()
{
    listen(socket_desc , 3);

    //Accept and incoming connection
    puts("Waiting for incoming connections...");
    c = sizeof(struct sockaddr_in);
    while( (new_socket = accept(socket_desc, (struct sockaddr *)&client, (socklen_t*)&c)) )
    {
        puts("Connection accepted");

        //Reply to the client
        reply();
    }

    if (new_socket<0)
    {
        perror("accept failed");
        return;
    }
}

void HttpServer::reply()
{
    message = "Hello Client , I have received your connection. And now I will assign a handler for you\n";
    write(new_socket , message , strlen(message));

    pthread_t sniffer_thread;
    new_sock = new int();
    *new_sock = new_socket;

    if( pthread_create( &sniffer_thread , NULL ,  HttpServer::connection_handler , this) < 0)
    {
        perror("could not create thread");
        return;
    }

    puts("Handler assigned");
}
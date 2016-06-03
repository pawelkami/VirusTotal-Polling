#include "HttpClient.h"
#include "exception/HttpClientException.h"
#include "Utils.h"
#include <memory>

void HttpClient::init()
{
    LOG_DEBUG("");
    port = (uint16_t)std::stoi(CONFIG.getValue("port"));

    struct sockaddr_in addr;
    struct hostent* server;
    memset(&addr, 0, sizeof(addr));
    memset(&server, 0, sizeof(server));

    // create socket
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if(sock < 0)
    {
        LOG_ERROR("creating socket failed - " + std::string(strerror(errno)));
        throw HttpClientException("Creating socket failed");
    }

    // lookup ip address
    std::string hostname = CONFIG.getValue("host");
    if(hostname.empty())
    {
        LOG_ERROR("No 'host' in configuration file");
        throw HttpClientException("No 'host' in configuration file");
    }

    server = gethostbyname(CONFIG.getValue("host").c_str());
    if(server == nullptr)
    {
        LOG_ERROR("No such host - " + std::string(strerror(h_errno)));
        return;
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    memcpy(&addr.sin_addr, server->h_addr, server->h_length );

    if(connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0 )
    {
        LOG_ERROR("Connection failed - " + std::string(strerror(errno)));
        close(sock);
        throw HttpClientException("Connection failed");
    }

    isSSL = port == SSL_PORT;
    if(isSSL)
    {
        SSL_load_error_strings();
        SSL_library_init();
        OpenSSL_add_all_algorithms();

        ssl_ctx = SSL_CTX_new (SSLv23_client_method());
        SSL_CTX_set_options(ssl_ctx, SSL_OP_SINGLE_DH_USE);

        conn = SSL_new(ssl_ctx);
        SSL_set_fd(conn, sock);

        if(SSL_connect(conn) < 0)
        {
            LOG_ERROR("SSL Connection failed");
            SSL_shutdown(conn);
            close(sock);
            throw HttpClientException("SSL Connection failed");
        }
    }
}

HttpClient::HttpClient()
{

}

HttpClient::~HttpClient()
{
    if(isSSL)
    {
        SSL_shutdown(conn);
        SSL_free(conn);
    }
    close(sock);
}


HttpResponse HttpClient::receiveResponse()
{
    std::string answer;
    answer = readData();
    return HttpResponse(answer);
}




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

void HttpClient::sendMsg(const HttpRequest &request)
{
    auto msg = request.getRequest();

    if(isSSL)
    {
        if(SSL_write(conn, msg.c_str(), (int)msg.length()) != (int)msg.length())
        {
            LOG_ERROR("Error SSL sending request.");
            return;
        }
    }
    else
    {
        if(send(sock, msg.c_str(), msg.length(), 0) != (int)msg.length())
        {
            LOG_ERROR("Error sending request.");
            return;
        }
    }
}

//HttpResponse HttpClient::receiveResponse()
//{
//    std::string answer;
//    int size_recv , total_size= 0;
//    struct timeval begin , now;
//    char answ[RCV_BUF_SIZE];
//    double timediff;
//
//    memset(answ, 0, sizeof(answ));
//    //make socket non blocking
//    fcntl(sock, F_SETFL, O_NONBLOCK);
//    //beginning time
//    gettimeofday(&begin , NULL);
//
//    while(1)
//    {
//        gettimeofday(&now , NULL);
//
//        timediff = (now.tv_sec - begin.tv_sec) + 1e-6 * (now.tv_usec - begin.tv_usec);
//
//        if( total_size > 0 && timediff > TIMEOUT )
//            break;
//        else if( timediff > TIMEOUT*2)
//            break;
//
//
//        memset(answ, 0 , sizeof(answ));  //clear the variable
//        if(isSSL)
//        {
//            if((size_recv =  SSL_read(conn, answ, sizeof(answ)) ) < 0)
//            {
//                usleep(100000);
//            }
//            else
//            {
//                total_size += size_recv;
//                answer += std::string(answ);
//                gettimeofday(&begin , NULL);
//            }
//        }
//        else
//        {
//            if((size_recv =  (int)recv(sock, answ , sizeof(answ), 0) ) < 0)
//            {
//                usleep(100000);
//            }
//            else
//            {
//                total_size += size_recv;
//                answer += std::string(answ);
//                gettimeofday(&begin , NULL);
//            }
//        }
//    }
//
//    return HttpResponse(answer);
//}

HttpResponse HttpClient::receiveResponse()
{
    std::string answer;

    //make socket non blocking
    fcntl(sock, F_SETFL, O_NONBLOCK);

    answer = readData();
    return HttpResponse(answer);
}



std::string HttpClient::readData()
{
    bool chunked = false;

    std::string line;
    std::string answer;

    // wczytywanie headerow
    do{
        line = readLine();
        std::cout << line;
        answer += line;
        if(line.find("chunked") != std::string::npos)
            chunked = true;

        if(line == "\r\n")
            break;

    } while(true);

    if(chunked)
        answer.append(readChunked());
    else
        answer.append(readNormally());


    return answer;
}

std::string HttpClient::readChunked()
{
    std::string answer;
    int chunkSize, n;
    std::string line;
    do{
        line = readLine();
        if(line == "\r\n")
            line = readLine();
        chunkSize = hextodec(line.substr(0, line.find_first_of("\r")));
        if(chunkSize == 0)
            break;

        while(chunkSize > 0)
        {

            line = readLine();
            chunkSize -= line.size();
            answer += line;
        }
    } while(true);

    return answer;
}


std::string HttpClient::readLine() {
    int n;
    std::string line;
    char c = '\0';

    while ( (isSSL ? n = SSL_read(conn, &c, 1) :  n = (int)recv( sock, &c, 1, 1 ) ) > 0 )
    {

        if ( c == '\r' )
        {
            line += c;

            if(isSSL)
                n = SSL_read(conn, &c, 1);
            else
                n = (int)recv( sock, &c, 1, MSG_PEEK );

            if ( ( n > 0 ) && ( c == '\n' ) )
            {
                if(!isSSL)
                    n = (int)recv( sock, &c, 1, 1 );
                line += c;
                break; // end of line
            }
        }
        line += c;
    }

    return line;
}

std::string HttpClient::readNormally()
{
    std::string answer;
    int size_recv , total_size= 0;
    struct timeval begin , now;
    char answ[RCV_BUF_SIZE];
    double timediff;

    memset(answ, 0, sizeof(answ));
    //make socket non blocking
    fcntl(sock, F_SETFL, O_NONBLOCK);
    //beginning time
    gettimeofday(&begin , NULL);

    while(1)
    {
        gettimeofday(&now , NULL);

        timediff = (now.tv_sec - begin.tv_sec) + 1e-6 * (now.tv_usec - begin.tv_usec);

        if( total_size > 0 && timediff > TIMEOUT )
            break;
        else if( timediff > TIMEOUT*2)
            break;


        memset(answ, 0 , sizeof(answ));  //clear the variable
        if(isSSL)
        {
            if((size_recv =  SSL_read(conn, answ, sizeof(answ)) ) < 0)
            {
                usleep(100000);
            }
            else
            {
                total_size += size_recv;
                answer += std::string(answ);
                gettimeofday(&begin , NULL);
            }
        }
        else
        {
            if((size_recv =  (int)recv(sock, answ , sizeof(answ), 0) ) < 0)
            {
                usleep(100000);
            }
            else
            {
                total_size += size_recv;
                answer += std::string(answ);
                gettimeofday(&begin , NULL);
            }
        }
    }
    return answer;
}
















#include <cstring>
#include <openssl/ssl.h>
#include <sys/socket.h>
#include <vector>
#include "HttpConnection.h"
#include "Utils.h"
#include "Logger.h"

std::string HttpConnection::readData()
{
    return readData(sock);
}

std::string HttpConnection::readChunk(int chunkSize)
{
    return readChunk(chunkSize, sock);
}

std::string HttpConnection::readChunked()
{
    return readChunked(sock);
}


std::string HttpConnection::readLine()
{
    return readLine(sock);
}

std::string HttpConnection::readNotChunked(int contentLength)
{
    return readNotChunked(contentLength, sock);
}

void HttpConnection::sendMsg(const std::string &msg)
{
    sendMsg(msg, sock);
}

std::string HttpConnection::receiveMsg()
{
    return readData();
}

HttpConnection::~HttpConnection()
{

}

void HttpConnection::sendMsg(const std::string &msg, int sock)
{
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

std::string HttpConnection::readData(int sock) {
    bool chunked = false;

    std::string line;
    std::string answer;

    int contentLength = 0;
    // Reading headers
    do{
        line = readLine(sock);
        answer += line;
        if(line.find("chunked") != std::string::npos)
            chunked = true;
        else if (line.find("Content-Length") != std::string::npos)
        {
            contentLength = stoi((line.substr(line.find_first_of(":") + 1, std::string::npos)));
        }

        if(line == "\r\n" || line == "")
        {
            break;
        }

    } while(true);

    if(chunked)
        answer.append(readChunked(sock));
    else
        answer.append(readNotChunked(contentLength, sock));


    return answer;
}

std::string HttpConnection::readChunk(int chunkSize, int sock)
{
    std::string answer;
    char answ[RCV_BUF_SIZE];

    memset(answ, 0, sizeof(answ));

    int bytesLeft = chunkSize;

    while(bytesLeft != 0)
    {
        int bytesToRead = bytesLeft > RCV_BUF_SIZE ? RCV_BUF_SIZE : bytesLeft;
        int n = isSSL ? SSL_read(conn, answ, bytesToRead) : recv(sock, answ, bytesToRead, 0);
        bytesLeft -= n;
        for(int i = 0; i < n; ++i)
            answer.push_back(answ[i]);

        memset(answ, 0, sizeof(answ));
    }
    return answer;
}

std::string HttpConnection::readChunked(int sock)
{
    std::string answer;
    int chunkSize;
    std::string line;
    line = readLine(sock);
    if(line == "\r\n")
        line = readLine(sock);
    chunkSize = hextodec(line.substr(0, line.find_first_of("\r")));

    while (chunkSize > 0)
    {
        answer += readChunk(chunkSize, sock);
        line = readLine(sock);
        if (line == "\r\n")
        {
            line = readLine(sock);
        }
        chunkSize = hextodec(line.substr(0, line.find_first_of("\r")));
    }
    readLine(sock);
    return answer;
}

std::string HttpConnection::readLine(int sock)
{
    int n;
    std::string line;
    char c = '\0';

    while ( (isSSL ? n = SSL_read(conn, &c, 1) :  n = (int)recv( sock, &c, 1, 0 ) ) > 0 )
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
                    n = (int)recv( sock, &c, 1, 0 );
                line += c;
                break; // end of line
            }
        }
        line += c;
    }
    return line;
}

std::string HttpConnection::readNotChunked(int contentLength, int sock)
{
    int bytesLeft = contentLength;
//    std::string answer;
    std::vector<char> answer;
    char answ[RCV_BUF_SIZE];

    memset(answ, 0, sizeof(answ));
    while(bytesLeft != 0)
    {
        int bytesToRead = bytesLeft > RCV_BUF_SIZE ? RCV_BUF_SIZE : bytesLeft;
        int n = isSSL ? SSL_read(conn, answ, bytesToRead) : recv(sock, answ, bytesToRead, 0);
        bytesLeft -= n;
        for(int i = 0; i < n; ++i)
            answer.push_back(answ[i]);

        memset(answ, 0, sizeof(answ));
    }
    return std::string(answer.begin(), answer.end());
}

std::string HttpConnection::receiveMsg(int sock)
{
    return readData(sock);
}



















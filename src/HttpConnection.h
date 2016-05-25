
#ifndef VIRUSTOTAL_POLLING_HTTPCONNECTION_H
#define VIRUSTOTAL_POLLING_HTTPCONNECTION_H


#include <string>
#include <openssl/ossl_typ.h>

#define RCV_BUF_SIZE 1024
#define SSL_PORT 443


class HttpConnection
{
protected:
    int sock;

    SSL *conn;

    SSL_CTX *ssl_ctx;

    uint16_t port;

    bool isSSL;

    virtual std::string readData();

    virtual std::string readChunk(int chunkSize);

    virtual std::string readChunked();

    virtual std::string readNotChunked(int size);

    virtual std::string readLine();

    virtual std::string readData(int sock);

    virtual std::string readChunk(int chunkSize, int sock);

    virtual std::string readChunked(int sock);

    virtual std::string readNotChunked(int size, int sock);

    virtual std::string readLine(int sock);

public:

    virtual ~HttpConnection();

    virtual void init() = 0;

    virtual void sendMsg(const std::string& buf);

    virtual void sendMsg(const std::string& msg, int sock);

    virtual std::string receiveMsg();

    virtual std::string receiveMsg(int sock);
};


#endif //VIRUSTOTAL_POLLING_HTTPCONNECTION_H

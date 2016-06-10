#ifndef VIRUSTOTAL_POLLING_VIRUSTOTALLOGIC_H
#define VIRUSTOTAL_POLLING_VIRUSTOTALLOGIC_H


#include <string>
#include "HttpClient.h"
#include <pthread.h>
#include <stdio.h>
#include <csignal>
#include <sys/time.h>
#include <stdlib.h>
#include <time.h>
#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <memory>

/**
 * Klasa odpowiadająca za logikę związaną z komunikację z serwisem VirusTotal
 */
class VirusTotalLogic
{
private:
    /**
     * Metoda wczytujaca plik z podanej sciezki i zwracajaca go w postaci string
     */
    std::string encodeData(const std::string& filePath);

    /**
     * Metoda pobierajaca zawartosc strony z podanego adresu.
     * Pobrana wartosc zapisuje sie poprzez referencje w zmiennej result.
     */
    void getContentFromAddress(const std::string &address, std::string &result);


    std::string getContentType();

    std::string getFilename(const std::string& filePath);

    /**
     * Obiekt klasy HttpClient sluzacy do komunikowania sie z serwisem VirusTotal.
     */
    HttpClient client;

    std::string boundary = "@@@BOUNDARY@@@";

    /**
     * Konfiguracja rezultatów, które mają zostać wypisane do pliku.
     */
    std::string resultConf;

    /**
     * Skrót sha256 badanego pliku.
     */
    std::string fileHash;

    /**
     * Identyfikator skanu zwrócony przez VirusTotal.
     */
    std::string scan_id;

    /**
     * Link pod ktorym znajduje sie raport z wykonanej analizy. Jest zwracany przez VT
     */
    std::string permalink;

    /**
     * Sciezka na dysku na ktorej znajduje sie badany plik
     */
    std::string virusPath;

    /**
     * Cialo analizowanego pliku.
     */
    std::string decodedFile;

    /**
     * Liczba cykli programu.
     */
    int numberOfCycles;
    int iterator;
    std::unique_ptr<boost::posix_time::seconds> inter;
    std::unique_ptr<boost::asio::deadline_timer> timer;
    boost::asio::io_service ioService;
    static VirusTotalLogic *instance;

    /**
     * Funkcja przygotowujaca wiadomosc wysyłaną podczas wysylania pliku do VirusTotal
     */
    std::string prepareFileToSend(const std::string& encoded);

    /**
     * Funkcja pobierajaca raport analizy pliku z serwisu.
     */
    std::string getReport();

    /**
     * Metoda inicjalizująca połączenie z VT
     */
    void initializeConnection();

    /**
     * Funkcja wysylajaca plik
     */
    void sendFile(const std::string &decoded);

    /**
     * Funkcja parsujaca wyniki z otrzymanego pliku HTML.
     * Korzysta z pliku konfiguracyjnego, w celu sprawdzenia co ma zostać wypisane.
     */
    std::string parseResults(const std::string& html);

    /**
     * Funkcja używana do wykonania ponownego przeskanowania pliku. Używa w tym celu zdefiniowane w klase sha256
     */
    void rescan();

    /**
     * Metoda zapisujaca wyniki analizy do pliku.
     */
    void saveResultsToFile(const std::string& results);

    /**
     * Funkcja do zastosowania ponownego skanowania pliku w trybie cyklicznym.
     */
    static void rescanCycling(const boost::system::error_code& /*e*/);

public:

    VirusTotalLogic();

    ~VirusTotalLogic();

    void setDecodedFile(const std::string &decoded);

    void setVirusPath(const std::string& path);

    void setResultConf(const std::string& resultConf);

    /**
     * Funkcja wywolywana w celu pozyskiwania raportow w trybie cyklicznym.
     */
    void getCyclicReport(int interval, int numberOfCycles, bool toRescan);

    /*
     * Funkcja zwracajaca zawartosc pliku z wynikami skanowania probki o podanym hashu
     */
    std::string getResult(const std::string& sha256);

    void setSHA256(const std::string& sha);

    /**
     * Funkcja przesylajaca do przeskanowania plik lokalny.
     */
    void scanFileLocal(const std::string& filepath);

    /**
     * Funkcja przesylajaca do przeskanowania zdekodowany plik.
     */
    void scanFileDecoded(const std::string& decoded);

    /**
     * Funkcja do przeprowadzenia ponownego skanowania pliku i zapisania raportu.
     */
    void rescanAndSaveReport();

};


#endif //VIRUSTOTAL_POLLING_VIRUSTOTALLOGIC_H

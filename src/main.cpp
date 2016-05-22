#include <boost/program_options.hpp>
#include <vector>
#include "Configuration.h"
#include "Logger.h"
#include "HttpClient.h"

using namespace std;

int main(int argc, char** argv)
{
    namespace po = boost::program_options;
    po::options_description description("Options");
    description.add_options()
            ("help,h", "Print this message")
            ("cycles,c", "Number of rescans")
            ("time,t", "Time between rescans")
            ("file", po::value<string>(), "File to scan");

    po::positional_options_description positionalDescription;
    positionalDescription.add("file", 1);


    po::variables_map vm;
    try
    {
        po::store(po::command_line_parser(argc, argv).options(description).positional(positionalDescription).run(),
                  vm);
        po::notify(vm);

        if (vm.count("help"))
        {
            std::cout << description << std::endl;
            return 0;
        }

    }
    catch(po::error& e)
    {
        std::cerr << "ERROR: " << e.what() << std::endl << std::endl;
        std::cerr << description << std::endl;
        return 0;
    }


    HttpClient http;

    HttpRequest request;
    request.putRequest(HttpMethod::GET, "/");
    request.putHeader("Host", "www.virustotal.com");
    request.putHeader("Accept", "*/*");
    request.putHeader("Connection", "Keep-Alive");

    http.init();
    http.sendMsg(request);
    std::cout << http.receiveResponse();

	return 0;
}
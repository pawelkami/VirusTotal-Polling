#include <boost/program_options.hpp>
#include <vector>
#include "Configuration.h"
#include "Logger.h"
#include "HttpClient.h"
#include "VirusTotalLogic.h"
#include "HttpServer.h"

using namespace std;
namespace po = boost::program_options;

po::variables_map handleParameters(int argc, char **argv);
void handler(const boost::system::error_code &ec);

int main(int argc, char** argv)
{
    po::variables_map vm = handleParameters(argc, argv);

    string filePath;
    if(vm.count("file"))
        filePath = vm["file"].as<string>();

    if (vm.count("cycles"))
    {
        VirusTotalLogic vtl;
        vtl.getCyclicReport(filePath, std::stoi(CONFIG.getValue("polling_interval_minutes_default")), vm.count("cycles"));
    }
    else if(vm.count("service"))
    {
        HttpServer::getInstance().startServer();
    }
    else
    {
        VirusTotalLogic vtl;
        vtl.scanFile(filePath);
    }

	return 0;
}

po::variables_map handleParameters(int argc, char **argv)
{
    po::options_description description("Options");
    description.add_options()
            ("help,h", "Print this message")
            ("cycles,c", po::value<int>(), "Number of rescans")
            ("time,t", po::value<int>(), "Time between rescans")
            ("file", po::value<string>(), "File to scan")
            ("service,s", "Start as service");

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
            cout << description << endl;
            exit(0);
        }

    }
    catch(po::error& e)
    {
        cerr << "ERROR: " << e.what() << endl << endl;
        cerr << description << endl;
        exit(0);
    }

    if (!vm.count("file")&& !vm.count("service"))
    {
        cout << "No file to scan" << endl;
        exit(0);
    }
    return vm;
}
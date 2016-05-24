#include <boost/program_options.hpp>
#include <vector>
#include "Configuration.h"
#include "Logger.h"
#include "HttpClient.h"
#include "VirusTotalLogic.h"
#include <boost/asio.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>

using namespace std;
namespace po = boost::program_options;

po::variables_map handleParameters(int argc, char **argv);
void handler(const boost::system::error_code &ec);

int main(int argc, char** argv)
{
    po::variables_map vm = handleParameters(argc, argv);

    string filePath = vm["file"].as<string>();

    if (vm.count("cycles"))
    {
        VirusTotalLogic vtl;
        vtl.getCyclicReport(filePath);
        boost::asio::io_service io;
        boost::asio::deadline_timer t(io);
        t.expires_from_now(boost::posix_time::seconds(std::stoi(CONFIG.getValue("polling_interval_minutes_default")) * vm.count("cycles") * 60));
        t.async_wait(handler);
        io.run();
    }
    else
    {
        VirusTotalLogic vtl;
        vtl.initializeConnection();
        vtl.setVirusPath(filePath);
        vtl.sendFile();
        std::string html = vtl.getReport();
        std::string results = vtl.parseResults(html);
        vtl.saveResultsToFile(results);
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

    if (!vm.count("file"))
    {
        cout << "No file to scan" << endl;
        exit(0);
    }
    return vm;
}

void handler(const boost::system::error_code &ec)
{
    std::cout << boost::posix_time::microsec_clock::local_time() << " Koniec cyklicznej pracy programu." << std::endl;
}
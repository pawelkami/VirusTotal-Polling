#include "Configuration.h"
#include <fstream>
#include "Logger.h"



Configuration::Configuration()
{
	readConfig();
}


Configuration::~Configuration()
{
}

Configuration & Configuration::getInstance()
{
	static Configuration instance;
	return instance;
}

void Configuration::readConfig()
{
	std::ifstream fin;
	fin.open(CONF_FILE_NAME);
	if (fin.is_open())
	{
        std::string jsonStr;
        std::string temp;
        while(std::getline(fin, temp))
            jsonStr += temp;

        json.init(jsonStr);
		fin.close();
	}

}

bool Configuration::has(std::string key)
{
    return json.has(key);
}

std::string Configuration::getValue(std::string key)
{
    return json.getValue(key);
}

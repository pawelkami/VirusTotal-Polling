#include "Configuration.h"
#include "external_libraries\json\reader.h"
#include <fstream>



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
	json::Reader reader;
	std::ifstream fin;
	fin.open(CONF_FILE_NAME);

	if (fin.is_open())
	{
		reader.Read(map, fin);
		fin.close();
	}

}

bool Configuration::has(std::string key)
{
	return map.Find(key) != map.End();
}

std::string Configuration::getValue(std::string key)
{
	if (has(key))
	{
		return json::String(map[key]);
	}
	return "";
}

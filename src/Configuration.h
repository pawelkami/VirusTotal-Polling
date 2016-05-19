#ifndef CONFIGURATION_H
#define CONFIGURATION_H

#include "json/reader.h"

#define CONF_FILE_NAME "virustotalpolling.conf"

class Configuration
{
private:
	Configuration();
	json::Object map;

public:
	~Configuration();

	static Configuration& getInstance();

	void readConfig();

	bool has(std::string key);
	std::string getValue(std::string key);
};


#endif
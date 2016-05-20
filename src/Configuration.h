#ifndef CONFIGURATION_H
#define CONFIGURATION_H

#include "json/reader.h"
#include "JsonObject.h"

#define CONF_FILE_NAME "virustotalpolling.conf"
#define CONFIG Configuration::getInstance()

class Configuration
{
private:
	Configuration();

	JsonObject json;

public:
	~Configuration();

	static Configuration& getInstance();

	void readConfig();

	bool has(std::string key);
	std::string getValue(std::string key);
};


#endif
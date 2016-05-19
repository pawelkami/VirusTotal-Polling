#include "Configuration.h"
#include "Logger.h"

using namespace std;

int main(int argc, char** argv)
{
	Configuration c = Configuration::getInstance();
	
	LOG_DEBUG("przed a=0");
	int a = 0;
	a++;
	LOG_ERROR("po a++");
	bool b = c.has("testowy");
	string s = c.getValue("testowy");
	return 0;
}
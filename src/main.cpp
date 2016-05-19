#include "Configuration.h"
#include "Logger.h"

using namespace std;

int main(int argc, char** argv)
{
	LOG_DEBUG("przed a=0");
	int a = 0;
	a++;
	LOG_ERROR("po a++");
	bool b = CONFIG.has("host");
	string s = CONFIG.getValue("host");
	return 0;
}
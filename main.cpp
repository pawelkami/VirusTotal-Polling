#include "Configuration.h"

using namespace std;

int main(int argc, char** argv)
{
	Configuration c = Configuration::getInstance();
	
	
	int a = 0;
	a++;
	bool b = c.has("testowy");
	string s = c.getValue("testowy");
	return 0;
}
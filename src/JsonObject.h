
#ifndef VIRUSTOTAL_POLLING_JSONOBJECT_H
#define VIRUSTOTAL_POLLING_JSONOBJECT_H

#include "json/reader.h"


class JsonObject
{
private:
    json::Object map;

public:
    void init(const std::string& json);

    bool has(const std::string& key);

    std::string getValue(const std::string& key);

};


#endif //VIRUSTOTAL_POLLING_JSONOBJECT_H

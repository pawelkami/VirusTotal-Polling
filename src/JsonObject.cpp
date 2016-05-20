
#include "JsonObject.h"

void JsonObject::init(const std::string &json)
{
    json::Reader reader;
    std::stringstream ss;
    ss << json;

    reader.Read(map, ss);

}

bool JsonObject::has(const std::string &key)
{
    return map.Find(key) != map.End();
}

std::string JsonObject::getValue(const std::string &key)
{
    if (has(key))
    {
        return json::String(map[key]);
    }

    return "";
}








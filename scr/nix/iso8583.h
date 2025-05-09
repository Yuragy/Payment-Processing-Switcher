#ifndef ISO8583_H
#define ISO8583_H

#include <cstdint>
#include <map>
#include <string>
#include <vector>

enum Encoding {
    ASCII,
    EBCDIC
};

enum FieldType {
    FIXED,
    LLVAR,
    LLLVAR
};

struct FieldDefinition {
    FieldType type;
    int length; 
};

struct DL_ISO8583_HANDLER {
    int version; 
    bool use_extended_fields; 
    Encoding encoding;
    std::map<int, FieldDefinition> field_definitions; 
};

struct DL_ISO8583_MSG {
    std::map<int, std::string> fields;
    std::vector<uint8_t> bitmap; 
};

struct DL_ISO8583_STRING {
    const uint8_t* ptr;
    size_t len;
};

#define DL_ISO8583_MSG_OK 0
#define DL_ISO8583_MSG_ERROR -1

int DL_ISO8583_DEFS_GetHandler(int version, DL_ISO8583_HANDLER* handler);
int DL_ISO8583_DEFS_1993_GetHandler(DL_ISO8583_HANDLER* handler); 
int DL_ISO8583_MSG_Init(DL_ISO8583_HANDLER* handler, DL_ISO8583_MSG* msg);
int DL_ISO8583_MSG_Unpack(DL_ISO8583_HANDLER* handler, const uint8_t* data, uint16_t len, DL_ISO8583_MSG* msg);
int DL_ISO8583_MSG_GetField_Str(int field, DL_ISO8583_STRING* str, const DL_ISO8583_MSG* msg);
int DL_ISO8583_MSG_SetField_Str(int field, const DL_ISO8583_STRING* str, DL_ISO8583_MSG* msg);
int DL_ISO8583_MSG_Pack(DL_ISO8583_HANDLER* handler, const DL_ISO8583_MSG* msg, uint8_t* data, uint16_t* len);
void DL_ISO8583_MSG_Free(DL_ISO8583_MSG* msg);

std::string EncodeField(const std::string& data, Encoding encoding);
std::string DecodeField(const std::string& data, Encoding encoding);
bool ValidateField(int field, const std::string& value, const DL_ISO8583_HANDLER& handler);
void LogMessage(const DL_ISO8583_MSG& msg);

#endif // ISO8583_H









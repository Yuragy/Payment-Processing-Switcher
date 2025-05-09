#include "iso8583.h"
#include <cstring>
#include <iostream>
#include <bitset>
#include <stdexcept>
#include <iomanip>

const int ISO8583_BITMAP_SIZE = 16;
const int ISO8583_MAX_FIELD_COUNT = 128;

const char EBCDIC_to_ASCII[256] = {
    0, 1, 2, 3, 156, 9, 134, 127, 151, 141, 142, 11, 12, 13, 14, 15,
    16, 17, 18, 19, 157, 133, 8, 135, 24, 25, 146, 143, 28, 29, 30, 31,
    128, 129, 130, 131, 132, 10, 23, 27, 136, 137, 138, 139, 140, 5, 6, 7,
    144, 145, 22, 147, 148, 149, 150, 4, 152, 153, 154, 155, 20, 21, 158, 26,
    32, 160, 226, 228, 224, 225, 227, 229, 231, 241, 162, 46, 60, 40, 43, 124,
    38, 233, 234, 235, 232, 237, 238, 239, 236, 223, 33, 36, 42, 41, 59, 172,
    45, 47, 194, 196, 192, 193, 195, 197, 199, 209, 166, 44, 37, 95, 62, 63,
    248, 201, 202, 203, 200, 205, 206, 207, 204, 185, 58, 35, 64, 39, 61, 34,
    216, 97, 98, 99, 100, 101, 102, 103, 104, 105, 171, 165, 217, 93, 245, 167,
    240, 106, 107, 108, 109, 110, 111, 112, 113, 114, 186, 161, 43, 187, 63, 191,
    126, 194, 115, 116, 117, 118, 119, 120, 121, 122, 169, 213, 224, 192, 164, 177,
    176, 193, 123, 193, 173, 234, 234, 234, 234, 123, 183, 189, 168, 199, 179, 236,
    202, 196, 215, 230, 173, 230, 190, 220, 219, 230, 162, 186, 167, 187, 177, 228,
    194, 245, 198, 199, 247, 166, 193, 172, 255, 204, 184, 173, 162, 181, 229, 173,
    206, 214, 207, 205, 202, 186, 204, 203, 206, 213, 227, 229, 174, 231, 186, 248,
    199, 228, 176, 232, 188, 173, 174, 188, 190, 173, 234, 233, 236, 250, 168, 169
};

const char ASCII_to_EBCDIC[256] = {
    0, 1, 2, 3, 55, 45, 46, 47, 22, 5, 37, 11, 12, 13, 14, 15,
    16, 17, 18, 19, 60, 61, 50, 38, 24, 25, 63, 39, 28, 29, 30, 31,
    64, 79, 127, 123, 91, 108, 80, 125, 77, 93, 92, 78, 107, 96, 75, 97,
    240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 122, 94, 76, 126, 110, 111,
    124, 193, 194, 195, 196, 197, 198, 199, 200, 201, 209, 210, 211, 212, 213, 214,
    215, 216, 217, 226, 227, 228, 229, 230, 231, 232, 233, 74, 224, 90, 95, 109,
    121, 129, 130, 131, 132, 133, 134, 135, 136, 137, 145, 146, 147, 148, 149, 150,
    151, 152, 153, 162, 163, 164, 165, 166, 167, 168, 169, 192, 106, 208, 161, 7,
    32, 33, 34, 35, 36, 21, 6, 23, 40, 41, 42, 43, 44, 9, 10, 27,
    48, 49, 26, 51, 52, 53, 54, 8, 56, 57, 58, 59, 4, 20, 62, 255,
    65, 170, 74, 177, 159, 178, 106, 201, 128, 131, 174, 189, 156, 174, 157, 152,
    232, 131, 167, 230, 127, 198, 240, 176, 121, 133, 172, 129, 237, 237, 238, 239,
    188, 109, 164, 165, 174, 228, 230, 170, 248, 174, 127, 232, 234, 241, 182, 197,
    175, 161, 153, 162, 169, 135, 246, 185, 189, 242, 179, 182, 180, 197, 174, 127,
    234, 170, 159, 172, 197, 242, 173, 172, 162, 166, 167, 187, 163, 163, 170, 130,
    197, 197, 175, 194, 237, 237, 237, 237, 237, 237, 237, 237, 237, 237, 237, 237
};

int DL_ISO8583_DEFS_GetHandler(int version, DL_ISO8583_HANDLER* handler) {
    handler->version = version;
    handler->use_extended_fields = false;
    handler->encoding = ASCII;

    handler->field_definitions = {
        {0, {FIXED, 4}},   // MTI
        {2, {LLVAR, 19}},  // PAN
        {3, {FIXED, 6}},   // Processing Code
        {4, {FIXED, 12}},  // Amount, Transaction
        {39, {FIXED, 2}},  // Response Code
        {55, {LLLVAR, 255}}, // ICC Data
        {62, {LLLVAR, 255}}, // Reserved National 3
        {38, {FIXED, 6}}   // Authorization Code
        // more
    };

    return DL_ISO8583_MSG_OK;
}

int DL_ISO8583_DEFS_1993_GetHandler(DL_ISO8583_HANDLER* handler) {
    return DL_ISO8583_DEFS_GetHandler(1993, handler);
}

int DL_ISO8583_MSG_Init(DL_ISO8583_HANDLER* handler, DL_ISO8583_MSG* msg) {
    msg->fields.clear();
    msg->bitmap.resize(ISO8583_BITMAP_SIZE, 0);
    return DL_ISO8583_MSG_OK;
}

int DL_ISO8583_MSG_Unpack(DL_ISO8583_HANDLER* handler, const uint8_t* data, uint16_t len, DL_ISO8583_MSG* msg) {
    if (len < 20) {
        return DL_ISO8583_MSG_ERROR;
    }

    uint16_t offset = 0;
    msg->fields[0] = std::string(reinterpret_cast<const char*>(data), 4);
    offset += 4;

    std::memcpy(msg->bitmap.data(), data + offset, ISO8583_BITMAP_SIZE);
    offset += ISO8583_BITMAP_SIZE;

    for (int i = 1; i <= ISO8583_MAX_FIELD_COUNT; ++i) {
        if (msg->bitmap[(i - 1) / 8] & (1 << (7 - ((i - 1) % 8)))) {
            FieldDefinition field_def = handler->field_definitions[i];
            uint16_t field_len = 0;

            if (field_def.type == FIXED) {
                field_len = field_def.length;
            } else if (field_def.type == LLVAR) {
                if (len - offset < 1) return DL_ISO8583_MSG_ERROR;
                field_len = data[offset];
                offset += 1;
            } else if (field_def.type == LLLVAR) {
                if (len - offset < 2) return DL_ISO8583_MSG_ERROR;
                field_len = (data[offset] << 8) | data[offset + 1];
                offset += 2;
            }

            if (len - offset < field_len) return DL_ISO8583_MSG_ERROR;
            std::string field_data(reinterpret_cast<const char*>(data + offset), field_len);
            msg->fields[i] = DecodeField(field_data, handler->encoding);
            offset += field_len;
        }
    }

    return DL_ISO8583_MSG_OK;
}

int DL_ISO8583_MSG_GetField_Str(int field, DL_ISO8583_STRING* str, const DL_ISO8583_MSG* msg) {
    auto it = msg->fields.find(field);
    if (it != msg->fields.end()) {
        str->ptr = reinterpret_cast<const uint8_t*>(it->second.c_str());
        str->len = it->second.size();
        return DL_ISO8583_MSG_OK;
    }
    return DL_ISO8583_MSG_ERROR;
}

int DL_ISO8583_MSG_SetField_Str(int field, const DL_ISO8583_STRING* str, DL_ISO8583_MSG* msg) {
    std::string field_data(reinterpret_cast<const char*>(str->ptr), str->len);
    if (!ValidateField(field, field_data, *handler)) {
        return DL_ISO8583_MSG_ERROR;
    }
    msg->fields[field] = EncodeField(field_data, handler->encoding);
    msg->bitmap[(field - 1) / 8] |= (1 << (7 - ((field - 1) % 8)));
    return DL_ISO8583_MSG_OK;
}

int DL_ISO8583_MSG_Pack(DL_ISO8583_HANDLER* handler, const DL_ISO8583_MSG* msg, uint8_t* data, uint16_t* len) {
    if (*len < 20) {
        return DL_ISO8583_MSG_ERROR;
    }

    uint16_t offset = 0;
    auto it = msg->fields.find(0);
    if (it != msg->fields.end()) {
        std::memcpy(data + offset, it->second.c_str(), 4);
        offset += 4;
    } else {
        return DL_ISO8583_MSG_ERROR;
    }

    std::memcpy(data + offset, msg->bitmap.data(), ISO8583_BITMAP_SIZE);
    offset += ISO8583_BITMAP_SIZE;

    for (const auto& field : msg->fields) {
        if (field.first == 0) continue;
        FieldDefinition field_def = handler->field_definitions[field.first];
        std::string encoded_field = EncodeField(field.second, handler->encoding);

        if (field_def.type == FIXED) {
            if (offset + field_def.length > *len) {
                return DL_ISO8583_MSG_ERROR;
            }
            std::memcpy(data + offset, encoded_field.c_str(), field_def.length);
            offset += field_def.length;
        } else if (field_def.type == LLVAR) {
            if (offset + 1 + encoded_field.size() > *len) {
                return DL_ISO8583_MSG_ERROR;
            }
            data[offset] = encoded_field.size();
            offset += 1;
            std::memcpy(data + offset, encoded_field.c_str(), encoded_field.size());
            offset += encoded_field.size();
        } else if (field_def.type == LLLVAR) {
            if (offset + 2 + encoded_field.size() > *len) {
                return DL_ISO8583_MSG_ERROR;
            }
            data[offset] = (encoded_field.size() >> 8) & 0xFF;
            data[offset + 1] = encoded_field.size() & 0xFF;
            offset += 2;
            std::memcpy(data + offset, encoded_field.c_str(), encoded_field.size());
            offset += encoded_field.size();
        }
    }

    *len = offset;
    return DL_ISO8583_MSG_OK;
}

void DL_ISO8583_MSG_Free(DL_ISO8583_MSG* msg) {
    msg->fields.clear();
    msg->bitmap.clear();
}

std::string EncodeField(const std::string& data, Encoding encoding) {
    if (encoding == ASCII) {
        return data;
    } else if (encoding == EBCDIC) {
        std::string encoded_data(data.size(), '\0');
        for (size_t i = 0; i < data.size(); ++i) {
            encoded_data[i] = ASCII_to_EBCDIC[static_cast<unsigned char>(data[i])];
        }
        return encoded_data;
    } else {
        throw std::invalid_argument("Unsupported encoding");
    }
}

std::string DecodeField(const std::string& data, Encoding encoding) {
    if (encoding == ASCII) {
        return data;
    } else if (encoding == EBCDIC) {
        std::string decoded_data(data.size(), '\0');
        for (size_t i = 0; i < data.size(); ++i) {
            decoded_data[i] = EBCDIC_to_ASCII[static_cast<unsigned char>(data[i])];
        }
        return decoded_data;
    } else {
        throw std::invalid_argument("Unsupported encoding");
    }
}

bool ValidateField(int field, const std::string& value, const DL_ISO8583_HANDLER& handler) {
    auto it = handler.field_definitions.find(field);
    if (it == handler.field_definitions.end()) {
        return false; 
    }
    const FieldDefinition& field_def = it->second;
    if (field_def.type == FIXED && value.size() != field_def.length) {
        return false; 
    }
    if ((field_def.type == LLVAR || field_def.type == LLLVAR) && value.size() > field_def.length) {
        return false; 
    }
    return true;
}

void LogMessage(const DL_ISO8583_MSG& msg) {
    std::cout << "ISO 8583 Message:" << std::endl;
    for (const auto& field : msg.fields) {
        std::cout << "Field " << field.first << ": " << field.second << std::endl;
    }
    std::cout << "Bitmap: ";
    for (uint8_t byte : msg.bitmap) {
        std::cout << std::bitset<8>(byte) << ' ';
    }
    std::cout << std::endl;
}



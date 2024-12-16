#ifndef _DEX_FORMAT_H_
#define _DEX_FORMAT_H_

#include <stdint.h>

#include <list>
#include <vector>
using namespace std;

#pragma pack(push, 4)

struct header_item {
  uint8_t magic[8];  // DEX_FILE_MAGIC
  uint32_t checksum;
  uint8_t signature[20];
  uint32_t file_size;
  uint32_t header_size;  // 0x70
  uint32_t endian_tag;   // ENDIAN_CONSTANT
  uint32_t link_size;
  uint32_t link_off;
  uint32_t map_off;
  uint32_t string_ids_size;
  uint32_t string_ids_off;
  uint32_t type_ids_size;
  uint32_t type_ids_off;
  uint32_t proto_ids_size;
  uint32_t proto_ids_off;
  uint32_t field_ids_size;
  uint32_t field_ids_off;
  uint32_t method_ids_size;
  uint32_t method_ids_off;
  uint32_t class_defs_size;
  uint32_t class_defs_off;
  uint32_t data_size;
  uint32_t data_off;
};

struct string_id_item {
  uint32_t string_data_off;  // points to string_data_item
};

struct type_id_item {
  uint32_t descriptor_idx;  // index of string_id_item list
};

struct proto_id_item {
  uint32_t shorty_idx;  // index of string_id_item list  //method declaration:
                        // return type + parameters type
  uint32_t return_type_idx;  // index of type_id_item list
  uint32_t parameters_off;   // points to type_list
};

struct field_id_item {
  uint16_t class_idx;  // index of type_id_item list //the class in which the
                       // field exists
  uint16_t type_idx;   // index of type_id_item list
  uint32_t name_idx;   // index of string_id_item list
};

struct method_id_item {
  uint16_t class_idx;  // index of type_id_item list //the class in which the
                       // method exists
  uint16_t proto_idx;  // index of proto_id_item list
  uint32_t name_idx;   // index of string_id_item list
};

struct class_def_item {
  uint32_t class_idx;          // index of type_id_item list
  uint32_t access_flags;       // ACCESS_FLAGS
  uint32_t superclass_idx;     // index of type_id_item list
  uint32_t interfaces_off;     // points to array of type_id_item (type_ids)
  uint32_t source_file_idx;    // index of string_id_item_list
  uint32_t annotations_off;    // points to array of annotations_directory_item
  uint32_t class_data_off;     // points to array of class_data_item
  uint32_t statis_values_off;  // points to array of encoded_array_item
};

struct dex_format {
 public:
  header_item header;
  vector<string_id_item> string_ids;
  vector<type_id_item> type_ids;
  vector<proto_id_item> proto_ids;
  vector<field_id_item> field_ids;
  vector<method_id_item> method_ids;
  vector<class_def_item> class_defs;
  vector<uint8_t> data;
  vector<uint8_t> link_data;
};

////////////////////////////////////////////////////////////////
enum DEX_ITEM_TYPE {
  TYPE_HEADER_ITEM = 0x0000,
  TYPE_STRING_ID_ITEM,
  TYPE_TYPE_ID_ITEM,
  TYPE_PROTO_ID_ITEM,
  TYPE_FIELD_ID_ITEM,
  TYPE_METHOD_ID_ITEM,
  TYPE_CLASS_DEF_ITEM,

  TYPE_MAP_LIST = 0x1000,
  TYPE_TYPE_LIST,
  TYPE_ANNOTATION_SET_REF_LIST,
  TYPE_ANNOTATION_SET_ITEM,

  TYPE_CLASS_DATA_ITEM = 0x2000,
  TYPE_CODE_ITEM,
  TYPE_STRING_DATA_ITEM,
  TYPE_DEBUG_INFO_ITEM,
  TYPE_ANNOTATION_ITEM,
  TYPE_ENCODED_ARRAY_ITEM,
  TYPE_ANNOTATIONS_DIRECTORY_ITEM,
};

struct map_item {
  uint16_t type;  // DEX_ITEM_TYPE
  uint16_t unused;
  uint32_t size;
  uint32_t offset;
};

struct map_list {
  uint32_t size;  // count of map_item
  vector<map_item> list;
};
////////////////////////////////////////////////////////////////

enum ACCESS_FLAGS {
  ACC_PUBLIC = 0x1,
  ACC_PRIVATE = 0x2,
  ACC_PROTECTED = 0x4,
  ACC_STATIC = 0x8,
  ACC_FINAL = 0x10,
  ACC_SYNCHRONIZED = 0x20,
  ACC_VOLATILE = 0x40,
  ACC_BRIDGE = 0x40,
  ACC_TRANSIENT = 0x80,
  ACC_VARARGS = 0x80,
  ACC_NATIVE = 0x100,
  ACC_INTERFACE = 0x200,
  ACC_ABSTRACT = 0x400,
  ACC_STRICT = 0x800,
  ACC_SYNTHETIC = 0x1000,
  ACC_ANNOTATION = 0x2000,
  ACC_ENUM = 0x4000,
  ACC_UNUSED = 0x8000,
  ACC_CONSTRUCTOR = 0x10000,
  ACC_DECLARED_ = 0x20000,
  SYNCHRONIZED,
};

////////////////////////////////////////////////////////////////
#pragma pack(push, 1)

struct string_data_item {
  uint32_t utf16_size;  // uleb128 //size of this string, in UTF-16 code units
  uint8_t data[1];
};

#pragma pack(pop)
////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////
struct type_item {
  uint16_t type_idx;  // index of type_id_item list
};

struct type_list {
  uint32_t size;
  vector<type_item> list;
};
////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////
struct try_item {
  uint32_t start_addr;  // start address of the block of code covered by this
                        // entry. The address is a count of 16-bit code units to
                        // the start of the first covered instruction.
  uint16_t insn_count;  // number of 16-bit code units covered by this entry.
                        // The last code unit covered(inclusive) is start_addr +
                        // insn_count - 1.
  uint16_t handler_off;  // offset in bytes in encoded_catch_handler_list
};

struct encoded_type_addr_pair {
  uint32_t type_idx;  // uleb128 //index of type_ids
  uint32_t addr;      // uleb128 //
};

struct encoded_catch_handler {
  int32_t size;  // sleb128
  vector<encoded_type_addr_pair> handlers;
  uint32_t
      catch_all_addr;  // uleb128 //bytecode address of the catch-all handler
};

struct encoded_catch_handler_list {
  uint32_t size;  // uleb128
  vector<encoded_catch_handler> list;
};

struct code_item {
  uint16_t registers_size;
  uint16_t ins_size;
  uint16_t outs_size;
  uint16_t tries_size;
  uint32_t debug_info_off;  // points to array of debug_info_item
  uint32_t insns_size;  // size of the instructions list, in 16-bit code units
  vector<uint16_t> insns;  // actual array of bytecode
  uint16_t padding;        // optional
  vector<try_item> tries;  // optional
  encoded_catch_handler_list handlers;
};

#pragma pack(push, 1)

struct encoded_field {
  uint32_t field_idx_diff;  // uleb128 //diff index of field_ids
  uint32_t access_flags;    // uleb128
};

struct encoded_method {
  uint32_t method_idx_diff;  // uleb128 //diff index of method_ids
  uint32_t access_flags;     // uleb128
  uint32_t code_off;         // uleb128 //points to array of code_item
};

struct class_data_item {
  uint32_t static_fields_size;             // uleb128
  uint32_t instance_fields_size;           // uleb128
  uint32_t direct_methods_size;            // uleb128
  uint32_t virtual_methods_size;           // uleb128
  vector<encoded_field> static_fields;     // count is static_fields_size
  vector<encoded_field> instance_fields;   // count is instance_fields_size
  vector<encoded_method> direct_methods;   // count is direct_methods_size
  vector<encoded_method> virtual_methods;  // count is virtual_methods_size
};

#pragma pack(pop)
////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////
enum VALUE_TYPE {
  VALUE_BYTE = 0x00,
  VALUE_SHORT = 0x02,
  VALUE_CHAR = 0x03,
  VALUE_INT = 0x04,
  VALUE_LONG = 0x06,
  VALUE_FLOAT = 0x10,
  VALUE_DOUBLE = 0x11,
  VALUE_STRING = 0x17,
  VALUE_TYPE = 0x18,
  VALUE_FIELD = 0x19,
  VALUE_METHOD = 0x1a,
  VALUE_ENUM = 0x1b,
  VALUE_ARRAY = 0x1c,
  VALUE_ANNOTATION = 0x1d,
  VALUE_NULL = 0x1e,
  VALUE_BOOLEAN = 0x1f,
};

#pragma pack(push, 1)

struct encoded_value {
  uint8_t value_arg_type;  //(value_arg << 5) | value_type
  vector<uint8_t> value;
};

struct encoded_array {
  uint32_t size;  // uleb128
  vector<encoded_value> values;
};

struct encoded_array_item {
  encoded_array value;
};

#pragma pack(pop)
////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////
enum VISIBILITY {
  VISIBILITY_BUILD = 0x0,
  VISIBILITY_RUNTIME = 0x1,
  VISIBILITY_SYSTEM = 0x2,
};

#pragma pack(push, 1)

struct annotation_element {
  uint32_t name_idx;  // uleb128 //index of string_ids
  encoded_value value;
};

struct encoded_annotation {
  uint32_t type_idx;                    // uleb128
  uint32_t size;                        // uleb128
  vector<annotation_element> elements;  // count is size
};

struct annotation_item {
  uint8_t visibility;  // VISIBILITY
  encoded_annotation annotation;
};

#pragma pack(pop)

struct annotation_off_item {
  uint32_t annotation_off;  // offset from the start of the file to an
                            // annotation. //points to anotation_item
};

struct annotation_set_item {
  uint32_t size;
  vector<annotation_off_item> entries;
};

struct annotation_set_ref_item {
  uint32_t annotations_off;  // offset from the start of the file to the
                             // referenced annotation
};

struct annotation_set_ref_list {
  uint32_t size;
  vector<annotation_set_ref_item> list;
};

struct field_annotation {
  uint32_t field_idx;        // index of field_ids
  uint32_t annotations_off;  // offset from the start of the file to the array
                             // of annotations for the field. //points to
                             // annotation_set_item
};

struct method_annotation {
  uint32_t method_idx;       // index of method_ids
  uint32_t annotations_off;  // offset from the start of the file to the array
                             // of annotations for the method. //points to
                             // annotation_set_item
};

struct parameter_annotation {
  uint32_t method_idx;       // index of method_ids
  uint32_t annotations_off;  // offset from the start of the file to the array
                             // of annotations for the method parameters.
                             // //points to annotation_set_ref_list
};

struct annotations_directory_item {
  uint32_t class_annotations_off;
  uint32_t fields_size;
  uint32_t annotated_methods_size;
  uint32_t annotated_parameters_size;
  vector<field_annotation>
      field_annotations;  // count is fields_size  //optional
  vector<method_annotation>
      method_annotations;  // count is annotated_methods_size //optional
  vector<parameter_annotation>
      parameter_annotations;  // count is annotated_parameters_size //optional
};
////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////
#pragma pack(push, 1)

struct packed_switch_payload {
  uint16_t ident;  // 0x0100
  uint16_t size;
  int32_t first_key;
  int32_t targets[1];
};

struct sparse_switch_payload {
  uint16_t ident;  // 0x0200
  uint16_t size;
  int32_t keys[1];
  int32_t targets[1];
};

struct fill_array_data_payload {
  uint16_t ident;  // 0x0300
  uint16_t element_width;
  uint32_t size;
  uint8_t data[1];
};

#pragma pack(pop)
////////////////////////////////////////////////////////////////

#pragma pack(pop)

#endif

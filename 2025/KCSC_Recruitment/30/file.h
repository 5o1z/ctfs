#ifndef FILE_H
#define FILE_H
#include<stdint.h>
#include<stdio.h>
#include<stdlib.h>
#define MAX_SEGMENT_SIZE 0x400
#define MAX_SEGMENT 0x10
#define MAX_FILE_SIZE MAX_SEGMENT*MAX_SEGMENT_SIZE
enum file_type
{
    Text = 1,
    Binary
};
typedef struct 
{
    char name[0x10];
    enum file_type type;
    size_t size;
    uint8_t no_segments;
    union
    {
        uint8_t *segments[MAX_SEGMENT];
        uint8_t data[0];
    };
}file;

file* allocate_file(char* name, enum file_type type, size_t size);
void delete_file(file* file_);
void read_text(uint8_t *data, size_t size);
void read_binary(uint8_t *data, size_t size);
void read_file(file* file_);
static inline uint32_t get_segment_id(size_t size);
void edit_file(file* file_, uint32_t offset, uint32_t size);
void print_text(file* file_);
void print_binary(file* file_);
void print_file(file* file_);
char* hexlify(const char *in,const size_t size);
void dump_file(file* file_); // for debug
#endif
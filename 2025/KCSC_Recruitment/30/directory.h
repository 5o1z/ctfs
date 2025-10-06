#ifndef DIRECTORY_H
#define DIRECTORY_H
#define MAX_FILE 0x10
#define MAX_SUB_DIR 0x10
#include"file.h"
#include"header.h"

typedef struct directory
{
    char name[0x10];
    struct directory* parent;
    uint32_t no_files, no_dirs;
    file* files[MAX_FILE];
    struct directory* dirs[MAX_SUB_DIR];
}directory;

typedef struct nameNode
{
    char *name;
    struct nameNode *next;
}nameNode;

directory* allocate_dir(char* name);
void add_dir(directory *parent, directory* child);
void add_file(directory *dir, file *file_);
void delete_dir(directory *dir);
int32_t search_file_in_dir(directory *dir, char *filename);
int32_t search_dir_in_dir(directory *dir, char *dirname);
void remove_file_in_dir(directory *dir, uint32_t index);
void remove_dir_in_dir(directory *dir, uint32_t index);
void pwd(directory *cur, nameNode *name);
void ls_dir(directory *dir);
void dump_dir(directory *dir);

#endif
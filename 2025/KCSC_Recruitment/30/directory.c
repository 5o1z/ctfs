#include"directory.h"
#include<string.h>

directory* allocate_dir(char* name)
{
    directory *dir;

    dir = (directory*)calloc(1, sizeof(directory));
    if(!dir)
        return NULL;
    
    strncpy(dir->name, name, sizeof(dir->name));
    dir->parent = dir;

#ifdef DEBUG
    printf("Allocate file\n");
    dump_dir(dir);
    puts("\n");
#endif
    return dir;
}

void add_dir(directory *parent, directory* child)
{
    if(parent->no_dirs < MAX_SUB_DIR)
    {
        parent->dirs[parent->no_dirs] = child;
        child->parent = parent;
        parent->no_dirs++;

#ifdef DEBUG
    dump_dir(parent);
    dump_dir(child);
#endif
    }
}

void add_file(directory *dir, file *file_)
{
    if(dir->no_files < MAX_FILE)
    {
        dir->files[dir->no_files] = file_;
        dir->no_files++;
    }
}

void delete_dir(directory *dir)
{
    for(uint32_t i = 0; i < dir->no_files; i++)
        delete_file(dir->files[i]);
    for(uint32_t i = 0; i < dir->no_dirs; i++)
        delete_dir(dir->dirs[i]);
    free(dir);
}

int32_t search_file_in_dir(directory *dir, char *filename)
{
    for(uint32_t i = 0; i < dir->no_files; i++)
        if(!strcmp(dir->files[i], filename))
            return i;
    return -1;
}

int32_t search_dir_in_dir(directory *dir, char *dirname)
{
    for(uint32_t i = 0; i < dir->no_dirs; i++)
        if(!strcmp(dir->dirs[i], dirname))
            return i;
    return -1;
}

void remove_file_in_dir(directory *dir, uint32_t index)
{
#ifdef DEBUG
    printf("Remove %s from %s\n", dir->files[index]->name, dir->name);
#endif
    delete_file(dir->files[index]);
    dir->files[index] = NULL;
    for(uint32_t i = index; i < dir->no_files - 1; i++)
        dir->files[i] = dir->files[i + 1];
    
    dir->no_files--;
    dir->files[dir->no_files] = NULL;
}

void remove_dir_in_dir(directory *dir, uint32_t index)
{
#ifdef DEBUG
    printf("Remove %s from %s\n", dir->dirs[index]->name, dir->name);
#endif
    delete_dir(dir->dirs[index]);
    dir->dirs[index] = NULL;
    for(uint32_t i = index; i < dir->no_dirs - 1; i++)
        dir->dirs[i] = dir->dirs[i + 1];

    dir->no_dirs--;
    dir->dirs[dir->no_dirs] = NULL;
}

void ls_dir(directory *dir)
{
    for(uint32_t i = 1; i <= dir->no_files; i++)
    {
        printf("%s     ", dir->files[i - 1]->name);
        if(i % 5 == 0)
            printf("\n");
    }
    for(uint32_t i = 1; i <= dir->no_dirs; i++)
    {
        printf("%s     ", dir->dirs[i - 1]->name);
        if(i % 5 == 0)
            printf("\n");
    }
    puts("");
}

void pwd(directory *cur, nameNode *name)
{
    if(cur->parent == cur)
    {
        printf("%s\n", cur->name);
        if(name)
        {
            printf("/");
            for(nameNode *node = name; node != NULL; node = node->next)
                printf("%s/", node->name);
            puts("");

            nameNode *tmp, *tmp2;
            tmp = name;
            while(tmp)
            {
                tmp2 = tmp->next;
                free(tmp);
                tmp = tmp2;
            }
        }
    }
    else
    {
        nameNode *node;

        node = (nameNode*)calloc(1, sizeof(nameNode));
        node->name = cur->name;
        node->next = name;    
        pwd(cur->parent, node);
    }
}

void dump_dir(directory *dir)
{
    printf("Directory name: %s\n", dir->name);
    printf("Parent: %s\n", dir->parent->name);
    printf("No files: %d\n", dir->no_files);
    printf("No dirs: %d\n", dir->no_dirs);
    ls_dir(dir);
}
#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<fcntl.h>
#include<string.h>
#include <stdint.h>
#include"file.h"
#include"directory.h"

uint8_t request[0x500];
directory *current_dir;

int is_alphanumeric(const char *str) {
    while (*str) {
        if (!isalnum(*str)) {
            return 0; // Return false if any character is not alphanumeric
        }
        str++;
    }
    return 1; // Return true if all characters are alphanumeric
}

void setup()
{
    current_dir = allocate_dir("/");
    if(!current_dir)
    {
        puts("Cannot allocate root");
        exit(-1);
    }
    setvbuf(stdin, 0, 2, 0);
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stderr, 0, 2, 0);
}


int main()
{
    char *cmd, *buf;
    setup();
    while(1)
    {
        //freopen("input.txt", "r", stdin);
        printf("> ");
        memset(request, '\0', sizeof(request));
        read(0, request, sizeof(request));
        cmd = strtok(request, " \n\0");
        if(cmd && !strcmp(cmd, "ls")) // ls
            ls_dir(current_dir);
        else if(cmd && !strcmp(cmd, "pwd")) // pwd
            pwd(current_dir, NULL);
        else if(cmd && !strcmp(cmd, "createfile")) // createfile <TYPE> <name> <size>
        {
            if(current_dir->no_files >= MAX_FILE)
            {
                puts("Cannot create more file in this directory");
                continue;
            }

            enum file_type ftype;
            char *type = strtok(NULL, " ");
            if(type && !strcmp(type, "text"))
                ftype = Text;
            else if(type && !strcmp(type, "binary"))
                ftype = Binary;
            else
            {
                puts("Invalid type");
                continue;
            }

            char *name = strtok(NULL, " ");
            if(!name || !is_alphanumeric(name))
            {
                puts("Invalid name");
                continue;
            }
            if(name && search_file_in_dir(current_dir, name) != -1)
            {
                puts("File already exists");
                continue;
            }


            buf = strtok(NULL, "\n\0");
            if(!buf)
                continue;
            uint32_t size = atoi(buf);
            if(size > MAX_FILE_SIZE)
            {
                puts("Invalid size");
                continue;
            }

            file *file_;
            file_ = allocate_file(name, ftype, size);
            
            if(!file_)
            {
                puts("Cannot allocate file");
                continue;
            }
            add_file(current_dir, file_);
            printf("Data: ");
            read_file(file_);
            puts("Done!");
        }
        else if(cmd && !strcmp(cmd, "createdir")) // createdir <name>
        {
            if(current_dir->no_dirs >= MAX_SUB_DIR)
            {
                puts("Cannot create more subdirectory in this directory");
                continue;
            }

            char *name = strtok(NULL, "\n\0");
            if(!name || !is_alphanumeric(name))
            {
                puts("Invalid name");
                continue;
            }
            if(search_dir_in_dir(current_dir, name) != -1)
            {
                puts("Subdirectory already exists");
                continue;
            }

            directory *dir = allocate_dir(name);
            if(!dir)
            {
                puts("Cannot allocate subdirectory");
                continue;
            }

            add_dir(current_dir, dir);
            puts("Done!");
        }
        else if(cmd && !strcmp(cmd, "cd")) // cd <dirname>
        {
            char *name = strtok(NULL, "\n\0");

            if(name && !strcmp(name, ".."))
                current_dir = current_dir->parent;
            else if(name && !strcmp(name, "."))
                goto Done;
            else if(name)
            {
                int32_t dir_index = search_dir_in_dir(current_dir, name);
                if(dir_index == -1)
                {
                    printf("%s doesn't exist!", name);
                    continue;
                }

                current_dir = current_dir->dirs[dir_index];
            }
#ifdef DEBUG
            printf("Change dir to %s\n", current_dir->name);
            puts("\n");
#endif
Done:
            puts("Done");
        }
        else if(cmd && !strcmp(cmd, "modifyfile")) // modifyfile <name> <offset> <size>
        {
            char *name = strtok(NULL, " \n\0");
            if(!name)
                continue;
            int32_t file_index = search_file_in_dir(current_dir, name);
            if(file_index == -1)
            {
                puts("File doesn't exist!");
                continue;
            }

            buf = strtok(NULL, " ");
            if(!buf)
                continue;
            uint32_t offset = atoi(buf);
            buf = strtok(NULL, " \n\0");
            if(!buf)
                continue;
            uint32_t size = atoi(buf);
            
            printf("New data: ");
            edit_file(current_dir->files[file_index], offset, size);
            puts("Done!");
        }
        else if(cmd && !strcmp(cmd, "removefile")) // removefile <name>
        {
            char *name = strtok(NULL, "\n\0");
            if(!name)
                continue;
            int32_t file_index = search_file_in_dir(current_dir, name);
            if(file_index == -1)
            {
                puts("File doesn't exist!");
                continue;
            }

            remove_file_in_dir(current_dir, file_index);
            puts("Done!");
        }
        else if(cmd && !strcmp(cmd, "removedir")) // removedir <name>
        {
            char *name = strtok(NULL, "\n\0");
            if(!name)
                continue;
            int32_t dir_index = search_dir_in_dir(current_dir, name);
            if(dir_index == -1)
            {
                puts("Directory doesn't exist!");
                continue;
            }

            remove_dir_in_dir(current_dir, dir_index);
            puts("Done!");
        }
        else if(cmd && !strcmp(cmd, "viewfile")) //viewfile <name>
        {
            char *name = strtok(NULL, "\n\0");
            if(!name)
                continue;
            int32_t file_index = search_file_in_dir(current_dir, name);
            if(file_index == -1)
            {
                puts("File doesn't exist!");
                continue;
            }

            printf("Data: ");
            print_file(current_dir->files[file_index]);
        }
        else
        {
            puts("");
            puts("ls                                : list files, subdirs");
            puts("pwd                               : get current directory path");
            puts("createfile <TYPE> <name> <size>   : create file in current directory");
            puts("createdir <name>:                 : create sub directory in current directory");
            puts("cd <dirname>                      : change directory(just 1 level at a time)");
            puts("modifyfile <name> <offset> <size> : modify file in current directory");   
            puts("removefile <name>                 : remove file in current directory");
            puts("removedir <name>                  : remove subdirectory");
            puts("viewfile <name>                   : view content of a file");
        }
    }
}
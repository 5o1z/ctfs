#include"file.h"
#include"header.h"
#include <unistd.h>
#include <ctype.h>
#include<string.h>

file* allocate_file(char* name, enum file_type type, size_t size)
{
    file *file_;
    uint8_t no_segments;
    if(size > MAX_SEGMENT_SIZE*MAX_SEGMENT)
        return NULL;
    if(size <= MAX_SEGMENT_SIZE)
    {
        file_ = (file*)calloc(1, sizeof(file) - MAX_SEGMENT*(sizeof(uint8_t*)) + size + 1); //1 is for NULL byte in text
        if(!file_)
            return NULL;
        file_->no_segments = 0;
    }
    else
    {
        no_segments = size / MAX_SEGMENT_SIZE;
        if(no_segments*MAX_SEGMENT_SIZE < size)
            no_segments++;
        file_ = (file*)calloc(1, sizeof(file));
        if(!file_)
            return NULL;
        file_->no_segments = no_segments;
        for(uint32_t i = 0; i < no_segments - 1; i++)
        {
            file_->segments[i] = (uint8_t*)calloc(1, MAX_SEGMENT_SIZE + 1);// 1 is for NULL byte in text
            if(!file_->segments[i])
                goto alloc_segment_fail;
        }
        size_t remaining_size = size - MAX_SEGMENT_SIZE*(file_->no_segments - 1);
        file_->segments[file_->no_segments - 1] = (uint8_t*)calloc(1, remaining_size + 1);// 1 is for NULL byte in text
        if(!file_->segments[file_->no_segments - 1])
            goto alloc_segment_fail;
    }
    strncpy(file_->name, name, sizeof(file_->name));
    file_->type = type;
    file_->size = size;
    goto success;

alloc_segment_fail:
    for(uint32_t i = 0; i < no_segments; i++)
        free(file_->segments[i]);
    free(file_);
    return NULL;
success:
#ifdef DEBUG
    dump_file(file_);
#endif
    return file_;
}

void delete_file(file* file_)
{
    if(file_->no_segments)
    {
        for(uint32_t i = 0; i < file_->no_segments; i++)
            free(file_->segments[i]);
    }
    free(file_);
}

void read_text(uint8_t *data, size_t size)
{
    char format[0x10];
    sprintf(format, "%%%ds", size); //format = "%{size}s"
    fflush(stdin);
    scanf(format, data);
}

void read_binary(uint8_t *data, size_t size)
{
    size_t nbytes = 0;
    while(nbytes < size)
    {   
        nbytes += read(0, &data[nbytes], size - nbytes);
        //printf("Error: %s\n", strerror(errno));
        //printf("Nbytes: %x\n", nbytes);
    }
}
void read_file(file* file_)
{
    //here i use scanf for text, read for binary
    if(!file_->no_segments)
    {
        if(file_->type == Text)
            read_text(file_->data, file_->size);
        else if(file_->type == Binary)
            read_binary(file_->data, file_->size);
    }
    else
    {
        for(uint32_t i = 0; i < file_->no_segments - 1; i++)
        {
            if(file_->type == Text)
                read_text(file_->segments[i], MAX_SEGMENT_SIZE);
            else if(file_->type == Binary)
                read_binary(file_->segments[i], MAX_SEGMENT_SIZE);
        }
        size_t remaining_size = file_->size - MAX_SEGMENT_SIZE*(file_->no_segments - 1);
        if(file_->type == Text)
            read_text(file_->segments[file_->no_segments - 1], remaining_size);
        else if(file_->type == Binary)
            read_binary(file_->segments[file_->no_segments - 1], remaining_size);
    }
}

static inline uint32_t get_segment_id(size_t size)
{
    return size / MAX_SEGMENT_SIZE;
}


void edit_file(file* file_, uint32_t offset, uint32_t size)
{
    if(offset >= file_->size) goto invalid;
    if(offset + size >= file_->size) goto invalid;

    if(file_->no_segments)
    {
        uint32_t segment_id, offset_in_segment;
        segment_id = get_segment_id(offset);
        offset_in_segment = offset % 0x400;
        if(file_->type == Text)
        {
            char inline_buf[MAX_SEGMENT_SIZE];
            read_text(inline_buf, size);
            memcpy(file_->segments[segment_id] + offset_in_segment,inline_buf, strlen(inline_buf));
            //read_text(file_->segments[segment_id] + offset_in_segment, size);
        }
        else if(file_->type == Binary)
            read_binary(file_->segments[segment_id] + offset_in_segment, size);
    }
#ifdef DEBUG
    //dump_file(file_);
#endif
invalid:
    return;
}

//https://github.com/AppImageCommunity/libappimage/blob/master/src/libappimage_shared/hexlify.c
char* hexlify(const char *bytes, const size_t numBytes)
{
    // first of all, allocate the new string
    // a hexadecimal representation works like "every byte will be represented by two chars"
    // additionally, we need to null-terminate the string
    char* hexlified = (char*) calloc((2 * numBytes + 1), sizeof(char));

    for (size_t i = 0; i < numBytes; i++) {
        char buffer[3];
        sprintf(buffer, "%02x", (unsigned char) bytes[i]);
        strcat(hexlified, buffer);
    }

    return hexlified;
}

void print_text(file* file_)
{
    if(!file_->no_segments)
        printf("%s\n", file_->data);
    else
    {
        for(uint32_t i = 0; i < file_->no_segments; i++)
            printf("%s", file_->segments[i]);
        printf("\n");
    }
}

void print_binary(file* file_)
{
    char *hex_str;
    if(!file_->no_segments)
    {
        hex_str = hexlify(file_->data, file_->size);
        printf("%s\n", hex_str);
        free(hex_str);
    }
    else
    {
        for(uint32_t i = 0; i < file_->no_segments - 1; i++)
        {
            hex_str = hexlify(file_->segments[i], MAX_SEGMENT_SIZE);
            printf("%s", hex_str);
            free(hex_str);
        }
        size_t remaining_size = file_->size - MAX_SEGMENT_SIZE*(file_->no_segments - 1);
        hex_str = hexlify(file_->segments[file_->no_segments - 1], remaining_size);
        printf("%s\n", hex_str);
        free(hex_str);
    }
}

void print_file(file* file_)
{
    if(file_->type == Text)
        print_text(file_);
    else
        print_binary(file_);
}

//for debug only
void dump_file(file* file_)
{
    printf("File is at %p\n", file_);
    printf("Chunk size: 0x%x\n", *(size_t*)((uint8_t*)file_ - 8));
    printf("File name: %s\n", file_->name);
    if(file_->type == Text)
        puts("Type: Text");
    else if(file_->type == Binary)
        puts("TYpe: Binary");
    else
    {
        puts("Type: ERROR");
        return;
    }
    printf("Total size: 0x%x\n", file_->size);
    printf("No segments: %d\n", file_->no_segments);
    if (file_->no_segments)
    {
        for (uint32_t i = 0; i < file_->no_segments; i++)
        {
            printf("Segment %d is at %p\n" ,i, file_->segments[i]);
            printf("Chunk size: 0x%x\n", *(size_t*)((uint8_t*)file_->segments[i] - 8));
        }
        
    }
    printf("Data: ");
    if(file_->type == Text)
        print_text(file_);
    else
        print_binary(file_);
}
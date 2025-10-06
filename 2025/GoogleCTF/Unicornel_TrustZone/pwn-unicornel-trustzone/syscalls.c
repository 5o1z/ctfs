#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <poll.h>
#include <pthread.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include "unicorn/unicorn.h"
#include "unicornel.h"

#define PAGE_SHIFT      12
#define PAGE_SIZE       (1UL << PAGE_SHIFT)
#define PAGE_MASK       (~(PAGE_SIZE-1))

#define PAGE_ALIGN(addr)        (((addr)+PAGE_SIZE-1)&PAGE_MASK)
#define TRUSTED_SYSCALL if(!current->trustzone_mode) return -0xff
char password[16] = { 0 };
/* I'm reusing MAX_PROCESSES here, but there's not a 1:1 mapping of shared buffers to processes.
 * a process can create multiple shared mappings */
struct shared_buffer shared_buffers[MAX_PROCESSES] = { 0 };
long create_shared(struct process* current) {
    // TRUSTED_SYSCALL;
    
    pthread_mutex_lock(&task_lock);
    unsigned long length = ARG_REGR(current,1);
    if(length > 0x10000 || !length || length & 0xFFF)
    {
        pthread_mutex_unlock(&task_lock);            
        return -1;
    }
    //Find an empty shared buffer handle
    unsigned long handle;
    for(handle = 0; handle < MAX_PROCESSES; handle++) {
        if(!shared_buffers[handle].refs)
            break;
    }
    if(handle == MAX_PROCESSES) {
        pthread_mutex_unlock(&task_lock);
        return -2;
    }
    void* buffer = calloc(1,length);
    if(!buffer) {
        pthread_mutex_unlock(&task_lock);
        return -3;
    }
    shared_buffers[handle].refs = 1;
    shared_buffers[handle].buffer = buffer;
    shared_buffers[handle].length = length;
    pthread_mutex_unlock(&task_lock);
    return handle;
}
long validate_handle(struct process* current) {
    TRUSTED_SYSCALL;

    pthread_mutex_lock(&task_lock);
    unsigned long handle = ARG_REGR(current,1);
    unsigned long length = ARG_REGR(current,2);
    if(handle >= MAX_PROCESSES || !shared_buffers[handle].refs || shared_buffers[handle].length < length) {
        pthread_mutex_unlock(&task_lock);
        return 0;
    }
    pthread_mutex_unlock(&task_lock);
    return (long) shared_buffers[handle].buffer;
}
long map_address(struct process* current)
{
    TRUSTED_SYSCALL;

    unsigned long addr = ARG_REGR(current,1);
    unsigned long length = ARG_REGR(current,2);
    void* buffer = (void*) ARG_REGR(current,3);
    fprintf(stderr,"Mapping %p @ %p length %lu\n",buffer,addr,length);
    uc_err e = uc_mem_map_ptr(current->uc,addr,length,UC_PROT_ALL,buffer);
    return e;
}
bool overlaps_tz(struct process* current,long src, unsigned n) {
    return current->trusted_zone_hook && !(src + n <= current->trustzone || current->trustzone + PAGE_ALIGN(current->tz_size) <= src);
}
uc_err safe_read(struct process* current, char* dst, long src, size_t n) {
    if(overlaps_tz(current,src,n)) TRUSTED_SYSCALL;
    return uc_mem_read(current->uc,src,dst,n);
}
uc_err strncpy_user(struct process* current, char* dst, long src, size_t n) {
    uc_err e;
    if(overlaps_tz(current,src,n)) TRUSTED_SYSCALL;
    for(unsigned i = 0; i < n; i++) {
        e = uc_mem_read(current->uc,src+i,dst+i,1);
        if(e != UC_ERR_OK)
            return e;
        if(!dst[i])
            return UC_ERR_OK;
    }
    dst[n-1] = 0;
    return UC_ERR_OK;
}

long unicornel_write(struct process* current) {
    unsigned long pointer = ARG_REGR(current,1);
    unsigned long length =  ARG_REGR(current,2);
    char* buffer = malloc(length);
    if(!buffer) return -1;
    uc_err err = safe_read(current,buffer,pointer,length);
    if(err != UC_ERR_OK) {
        free(buffer);
        return -1;
    }
    long ret = write(current->outfd,buffer,length);
    free(buffer);
    return ret;
}
//You're welcome
long print_integer(struct process* current) {
    dprintf(current->outfd,"%ld\n",ARG_REGR(current,1));
    return 0;
}
//Also called when the trustzone returns
long unicornel_exit(struct process* current) {
    uc_emu_stop(current->uc);
    return 0;
}

long unicornel_pause(struct process* current) {
    current->paused = true;
    while(current->paused);
    return 0;
}
long unicornel_resume(struct process* current) {
    unsigned long pid = ARG_REGR(current,1);
    pthread_mutex_lock(&task_lock);
    if(pid > MAX_PROCESSES || !processes[pid] || !processes[pid]->paused)
    {
        pthread_mutex_unlock(&task_lock);
        return -1;
    }
    processes[pid]->paused = false;
    pthread_mutex_unlock(&task_lock);
    return 0;
}
//The trustzone is allowed to access trusted memory, no one else is.
void trusted_read(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void* user_data) {
    struct process* current = user_data;
    fprintf(stderr,"TRUSTED READ: %p %p\n",address,current->trustzone);
    if(!current->trustzone_mode) {
        //Untrusted code tried to access trusted memory, abort the malicious process
        printf("Unprivileged access to trustzone attempted! Killing process\n");
        uc_emu_stop(uc);
    }
}
long memprot(struct process* current) {
    TRUSTED_SYSCALL;
    unsigned long addr = ARG_REGR(current,1);
    unsigned long length = ARG_REGR(current,2);
    unsigned long prot = ARG_REGR(current,3);
    return uc_mem_protect(current->uc,addr,length,prot);
}
long create_trustzone(struct process* current) {
    if(current->trusted_zone_hook)
        return -1;
    uc_engine* uc = current->uc;
    unsigned long addr = ARG_REGR(current,1);
    unsigned long filename_user = ARG_REGR(current,2);
    char filename[128] = { 0 };
    uc_err err = strncpy_user(current,filename,filename_user,sizeof(filename));
    if(err != UC_ERR_OK) {
        printf("Failed to copy string from address %p\n",filename_user);
        return -1;
    }
    for(unsigned i = 0; i < sizeof(filename); i++) {
        if(filename[i] == '.' || filename[i] == '/') {
            filename[i] = '_';
        }
    }
    int fd = open(filename,O_RDONLY);
    if(fd == -1) {
        printf("Failed to open trustzone %s %m\n",filename);
        return errno;
    }
    off_t size = lseek(fd,0,SEEK_END);
    err = uc_mem_map(uc,addr,PAGE_ALIGN(size),UC_PROT_READ | UC_PROT_EXEC);
    if(err != UC_ERR_OK)
    {
      printf("Failed on uc_mem_map() with error %u\n",err);
      close(fd);
      return -1;
    }
    err = uc_hook_add(uc,&current->trusted_zone_hook,UC_HOOK_MEM_READ,trusted_read,current,addr,addr+PAGE_ALIGN(size));
    if(err != UC_ERR_OK) {
      printf("Failed on uc_hook_add() with error %u\n",err);
      close(fd);
      uc_mem_unmap(uc,addr,PAGE_ALIGN(size));
      return -1; 
    }
    char* file = calloc(size,1);
    lseek(fd,0,SEEK_SET);
    read(fd,file,size);
    uc_mem_write(uc,addr,file,size);
    current->trustzone = addr;
    current->tz_size = size;
    close(fd);
    fprintf(stderr,"Trustzone allocated at %p %lu\n",addr,PAGE_ALIGN(size));
    return 0;
}
long destroy_trustzone(struct process* current) {
    if(!current->trusted_zone_hook)
        return -1;
    uc_mem_unmap(current->uc,current->trustzone,PAGE_ALIGN(current->tz_size));
    uc_hook_del(current->uc,current->trusted_zone_hook);
    current->trusted_zone_hook = false;
    current->trustzone = 0;
    current->tz_size = 0;
    return 0;
}
long confirm_password(struct process* current) {
    TRUSTED_SYSCALL;
    if(!password[0]) {
        int password_fd = open("password",O_RDONLY);
        if(password_fd == -1)
        {
            printf("open password failed: %m\n");
            abort();
        }
        read(password_fd,password,16);
        close(password_fd);
    }
    char user_password[sizeof(password)];
    uc_err e = strncpy_user(current,user_password,ARG_REGR(current,1),sizeof(user_password));
    if(e != UC_ERR_OK) {
        return 1;
    }
    return !!strncmp(user_password,password,sizeof(user_password));
}
long trustzone_invoke(struct process* current) {
    if(!current->trusted_zone_hook)
        return -1;
    current->trustzone_mode = true;
    unsigned long ip = 0;
    uc_reg_read(current->uc,ip_reg[current->arch],&ip);

    uc_err err = uc_emu_start(current->uc,current->trustzone,current->trustzone + current->tz_size,0,0);
    current->trustzone_mode = false;
    fprintf(stderr,"trustzone over %s\n",uc_strerror(err));
    uc_reg_write(current->uc,ip_reg[current->arch],&ip);
    return err;
}

long (*syscalls[])(struct process* current) = {
    unicornel_exit, //0
    unicornel_write, //1
    print_integer, //2
    create_shared, //3
    validate_handle, //4
    map_address, //5
    unicornel_pause, //6
    unicornel_resume, //7
    create_trustzone, //8
    destroy_trustzone, //9
    trustzone_invoke, //10
    confirm_password, //11
    memprot, //12
};

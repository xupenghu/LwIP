#ifndef __SYS_ARCH_H__
#define __SYS_ARCH_H__

/*
#include    "os_cpu.h"
#include    "os_cfg.h"
#include    "ucos_ii.h"


#define LWIP_STK_SIZE      2048

//yangye 2003-1-27
//defines for sys_thread_new() & sys_arch_timeouts()
//max number of lwip tasks
#define LWIP_TASK_MAX    3
//first prio of lwip tasks
#define LWIP_START_PRIO  5   //so priority of lwip tasks is from 5-9 


#define SYS_MBOX_NULL   (void*)0
#define SYS_SEM_NULL    (void*)0
#define MAX_QUEUES        10
#define MAX_QUEUE_ENTRIES 10

typedef struct {
    OS_EVENT*   pQ;
    void*       pvQEntries[MAX_QUEUE_ENTRIES];
} TQ_DESCR, *PQ_DESCR;
    
typedef OS_EVENT* sys_sem_t;
typedef PQ_DESCR  sys_mbox_t;
typedef INT8U     sys_thread_t;
*/

#include    "includes.h"

/* HANDLE is used for sys_sem_t but we won't include windows.h */
typedef OS_EVENT* sys_sem_t;
#define SYS_SEM_NULL NULL
#define sys_sem_valid(sema) ((*sema) != NULL)
#define sys_sem_set_invalid(sema) ((*sema) = NULL)

/* let sys.h use binary semaphores for mutexes */
#define LWIP_COMPAT_MUTEX 1

#ifndef MAX_QUEUE_ENTRIES
#define MAX_QUEUE_ENTRIES 100
#endif
struct lwip_mbox {
  sys_sem_t sem;
  sys_sem_t mutex;
  void* q_mem[MAX_QUEUE_ENTRIES];
  u32_t head, tail;
  u32_t msg_num; 
};
typedef struct lwip_mbox sys_mbox_t;
#define SYS_MBOX_NULL NULL
#define sys_mbox_valid(mbox) ((mbox != NULL) && ((mbox)->sem != NULL))
#define sys_mbox_set_invalid(mbox) ((mbox)->sem = NULL)

/* DWORD (thread id) is used for sys_thread_t but we won't include windows.h */
typedef INT8U sys_thread_t;



/*
//Mbox num must larger than MEMP_NUM_NETCONN
#define TOTAL_MBOX_NUM  5	//定义内核能够使用的最多邮箱数目
#define MAX_MSG_IN_MBOX 100	//每个邮箱最多能够存放的消息数目

//定义内核使用的邮箱的结构
struct LWIP_MBOX_STRUCT{
	OS_EVENT * ucos_queue;						//借助ucos中的队列机制来实现
	void     *mbox_msg_entris[MAX_MSG_IN_MBOX];//邮箱中存放消息的指针
};

//定义LwIP内部使用的数据类型
typedef struct LWIP_MBOX_STRUCT* sys_mbox_t;  //系统邮箱类型指针
typedef OS_EVENT* sys_sem_t;                  //系统信号量类型指针
typedef INT8U     sys_thread_t;				  //系统任务标识

#define LWIP_COMPAT_MUTEX 1

//信号NULL, 邮箱NULL 定义  
#define SYS_MBOX_NULL  (sys_mbox_t)NULL
#define SYS_SEM_NULL   (sys_sem_t)NULL
*/
#endif

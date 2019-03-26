#ifndef __SYS_ARCH_H__
#define __SYS_ARCH_H__


#include    "includes.h"	//包含操作系统相关头文件

/* HANDLE is used for sys_sem_t but we won't include windows.h */
typedef OS_EVENT* sys_sem_t;		//定义信号量类型为操作系统上的一个事件指针
#define SYS_SEM_NULL NULL		//空信号量
#define sys_sem_valid(sema) ((*sema) != NULL)	//判断sema指向的信号量是否为空
#define sys_sem_set_invalid(sema) ((*sema) = NULL)	//将sema指向的信号量置为无效

/* let sys.h use binary semaphores for mutexes */
/* 定义互斥量相关的类型和宏*/
#define LWIP_COMPAT_MUTEX 1		//定义该值为1 则内核自动基于信号量函数来实现互斥量函数

/*定义邮箱相关的类型和宏 这里邮箱采用环形缓冲机制来实现*/
#ifndef MAX_QUEUE_ENTRIES
#define MAX_QUEUE_ENTRIES 100		//定义邮箱可缓冲的最大消息数量
#endif
struct lwip_mbox {	//邮箱结构体类型定义
  sys_sem_t sem;	//信号量 用于邮箱内消息的同步访问
  sys_sem_t mutex;	//互斥锁 用户邮箱缓冲区的互斥访问
  void* q_mem[MAX_QUEUE_ENTRIES];	//邮箱环形缓冲区 一个数组指针类型 
  u32_t head, tail;		//缓冲区头部和尾部 head表示下一条写入的消息再环形缓冲区中的位置 
  						//tail 表示下一条读取的信息在环形缓冲区中的位置
  
  u32_t msg_num; 	//缓冲区中消息数量			   	记录了当前邮箱中的消息数据
};
typedef struct lwip_mbox sys_mbox_t; //定义邮箱消息类型
#define SYS_MBOX_NULL NULL	//空邮箱
/* 判断mbox指向的邮箱是否有效*/
#define sys_mbox_valid(mbox) ((mbox != NULL) && ((mbox)->sem != NULL))	
/* 将mbox指向的邮箱设置为无效 */
#define sys_mbox_set_invalid(mbox) ((mbox)->sem = NULL)

/* DWORD (thread id) is used for sys_thread_t but we won't include windows.h */
typedef INT8U sys_thread_t; //线程ID 也就是任务优先级


#endif

/*
 * Copyright (c) 2001, Swedish Institute of Computer Science.
 * All rights reserved. 
 *
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions 
 * are met: 
 * 1. Redistributions of source code must retain the above copyright 
 *    notice, this list of conditions and the following disclaimer. 
 * 2. Redistributions in binary form must reproduce the above copyright 
 *    notice, this list of conditions and the following disclaimer in the 
 *    documentation and/or other materials provided with the distribution. 
 * 3. Neither the name of the Institute nor the names of its contributors 
 *    may be used to endorse or promote products derived from this software 
 *    without specific prior written permission. 
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND 
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE 
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL 
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS 
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) 
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT 
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY 
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF 
 * SUCH DAMAGE. 
 *
 * This file is part of the lwIP TCP/IP stack.
 * 
 * Author: Adam Dunkels <adam@sics.se>
 *
 * $Id: sys_arch.c,v 1.1.1.1 2003/05/17 05:06:56 chenyu Exp $
 */
#if !NO_SYS

#include "def.h"
#include "sys.h"
#include "err.h"
//ucosii的内存管理结构，我们将所有邮箱空间通过内存管理结构来管理

/*
static OS_MEM *MboxMem;
static char MboxMemoryArea[TOTAL_MBOX_NUM * sizeof(struct LWIP_MBOX_STRUCT)];
const u32_t NullMessage;//解决空指针投递的问题
*/

//定义系统使用的超时链表首指针结构
//struct sys_timeouts global_timeouts;
//与系统任务新建函数相关的变量定义

#define LWIP_MAX_TASKS 4 	//允许内核最多创建的任务个数
#define LWIP_STK_SIZE  512	//每个任务的堆栈空间
OS_STK  LWIP_STK_AREA[LWIP_MAX_TASKS][LWIP_STK_SIZE]; //任务的堆栈空间


void sys_init()
{
  //currently do nothing
  //Printf("[Sys_arch] init ok");
}

/*
*创建一个信号量 信号量初始值为count 若创建成功 则返回值为ERR_OK 切sem指向成功
*创建的信号量；否则返回非成功值 表示创建失败
*/
err_t sys_sem_new(sys_sem_t *sem, u8_t count)
{
  OS_EVENT *new_sem = NULL;

  LWIP_ASSERT("[Sys_arch]sem != NULL", sem != NULL);

  new_sem = OSSemCreate((u16_t)count);	//利用操作系统创建一个信号量
  LWIP_ASSERT("[Sys_arch]Error creating sem", new_sem != NULL);
  if(new_sem != NULL) {	//如果创建成功
    *sem = (void *)new_sem;	//记录信号量
    return ERR_OK;
  }
   
  *sem = SYS_SEM_NULL;	//赋值为空
  return ERR_MEM;	//创建失败返回
}
/* 删除指向sem的信号量 */
void sys_sem_free(sys_sem_t *sem)
{
  u8_t Err;
  // parameter check 
  LWIP_ASSERT("sem != NULL", sem != NULL);
  
  OSSemDel(*sem, OS_DEL_ALWAYS, &Err);	//直接调用操作系统函数删除信号量
	
  if(Err != OS_ERR_NONE)  //如果删除失败 
  {
    //add error log here
    //Printf("[Sys_arch]free sem fail\n");
  }

  *sem = NULL;
}

/*
* 等待信号量 如果timeout = 0 则一直阻塞等待 知道信号量的到来；如果timeout不等于0 
* 表示组赛的最大等待毫秒数 这种情况下 函数返回值为在该信号量上等待所花费的时间，如果在
* 等待timeout时间后还没有等来信号量 则返回SYS_ARCH_TIMEOUT 如果不用等待就可以使用该信号量
* 则返回值为0
*/
u32_t sys_arch_sem_wait(sys_sem_t *sem, u32_t timeout)
{
  u8_t Err;
  u32_t wait_ticks;
  u32_t start, end;
  LWIP_ASSERT("sem != NULL", sem != NULL);

  if (OSSemAccept(*sem))		  // 如果已经收到, 则返回0 
  {
	  //Printf("debug:sem accept ok\n");
	  return 0;
  }   
  /* 将等待的毫秒数 转化为操作系统的对用的时钟滴答数 */
  wait_ticks = 0;
  if(timeout!=0){
	 wait_ticks = (timeout * OS_TICKS_PER_SEC)/1000;	
	 if(wait_ticks < 1)	//等待范围取舍
		wait_ticks = 1;
	 else if(wait_ticks > 65535)
			wait_ticks = 65535;
  }

  start = sys_now();	//开始等待
  OSSemPend(*sem, (u16_t)wait_ticks, &Err);
  end = sys_now();	//结束等待
  
  if (Err == OS_NO_ERR)		//如果成功等待到了信号量
		return (u32_t)(end - start);		//返回阻塞时间
  else
		return SYS_ARCH_TIMEOUT;
  
}

/* 释放一个信号量 */
void sys_sem_signal(sys_sem_t *sem)
{
  u8_t Err;
  LWIP_ASSERT("sem != NULL", sem != NULL);

  Err = OSSemPost(*sem);	//直接调用系统函数释放信号量
  if(Err != OS_ERR_NONE)	//如果释放失败
  {
        //add error log here
        //Printf("[Sys_arch]:signal sem fail\n");
  }
  
  LWIP_ASSERT("Error releasing semaphore", Err == OS_ERR_NONE);
}

/*
* 创建一个邮箱 邮箱所能容纳的消息数为size，邮箱内消息的本质是指针，它指向了消息的具体位置；
* 本创建中，忽略了size 采用默认的MAX_QUEUE_ENTRIES大小
*
*
*/
err_t sys_mbox_new(sys_mbox_t *mbox, int size)
{
  err_t err;
  LWIP_ASSERT("mbox != NULL", mbox != NULL);
  LWIP_UNUSED_ARG(size);	//忽略size

  err = sys_sem_new(&(mbox->sem), 0);	//创建邮箱上的信号量 用于同步
  //LWIP_ASSERT("Error creating semaphore", err == ERR_OK);
  if(err != ERR_OK) {	//创建失败 返回内存错误
  	//Printf("[Sys_arch]:signal sem fail\n");
    return ERR_MEM;
  }
  err = sys_mutex_new(&(mbox->mutex));	//创建互斥锁 创建失败则返回内存错误
  LWIP_ASSERT("Error creating mutex", err == ERR_OK);
  if(err != ERR_OK) {
  	sys_sem_free(&(mbox->sem));	//清空已申请的邮箱
    return ERR_MEM;
  }
  //初始化缓冲区
  memset(&mbox->q_mem, 0, sizeof(void *)*MAX_QUEUE_ENTRIES);	//清空缓冲区数据
  mbox->head = 0;	
  mbox->tail = 0;
  mbox->msg_num = 0;
  
  return ERR_OK;
}

/* 
* 删除邮箱    如果删除过程中邮箱中还包含有消息 说明用户应用程序编写错误 从而导致了这种异常   
* 用户应该极力避免这种异常
* 
*/
void sys_mbox_free(sys_mbox_t *mbox)
{
  /* parameter check */
  u8_t Err;
  LWIP_ASSERT("mbox != NULL", mbox != NULL);
  
  sys_sem_free(&(mbox->sem));	//释放信号量
  sys_mutex_free(&(mbox->mutex));	//释放互斥锁

  mbox->sem = NULL;
  mbox->mutex = NULL;
}

/* 向邮箱发送一条信息，如果发送队列满，则这个函数被阻塞，直到发送成功为止 */
void sys_mbox_post(sys_mbox_t *q, void *msg)
{
  u8_t Err;
  //SYS_ARCH_DECL_PROTECT(lev);

  /* parameter check */
  LWIP_ASSERT("q != SYS_MBOX_NULL", q != SYS_MBOX_NULL);
  LWIP_ASSERT("q->sem != NULL", q->sem != NULL);

  //queue is full, we wait for some time 
  /* 发送缓冲区满 则等待并重试 */
  while(q->msg_num >= MAX_QUEUE_ENTRIES)
  {
    sys_msleep(1);
  }
  
  //SYS_ARCH_PROTECT(lev);
  sys_mutex_lock(&(q->mutex));	//上锁 防止重复访问
  if(q->msg_num >= MAX_QUEUE_ENTRIES)	//在等待锁期间 缓冲区又被填满 无法处理这种竞争条件
  {
    LWIP_ASSERT("mbox post error, we can not handle it now, Just drop msg!", 0);
	//SYS_ARCH_UNPROTECT(lev);
	sys_mutex_unlock(&(q->mutex));	 //释放互斥锁
	return;	//返回 忽略消息投递
  }
  q->q_mem[q->head] = msg;	//写入数据
  (q->head)++;	//调节写入指针
  if (q->head >= MAX_QUEUE_ENTRIES) {	//若指针已达到缓冲区末尾
    q->head = 0;	//则调整指针为缓冲区头部
  }

  q->msg_num++;	//增加消息计数
  if(q->msg_num == MAX_QUEUE_ENTRIES)	//如果队列满
  {
    //Printf("mbox post, box full\n");
  }
  
  //Err = OSSemPost(q->sem);
  sys_sem_signal(&(q->sem));	//消息正常投递 释放信号量
  sys_mutex_unlock(&(q->mutex)); //释放互斥锁 释放访问
}

/* 不阻塞尝试发送一条信息 如果发送成功 返回ERR_OK 否则返回ERR_MEM */
err_t sys_mbox_trypost(sys_mbox_t *q, void *msg)
{
  u8_t Err;
  //SYS_ARCH_DECL_PROTECT(lev);

  /* parameter check */
  LWIP_ASSERT("q != SYS_MBOX_NULL", q != SYS_MBOX_NULL);
  LWIP_ASSERT("q->sem != NULL", q->sem != NULL);

  //SYS_ARCH_PROTECT(lev);
  sys_mutex_lock(&(q->mutex));	//互斥上锁 防止同时访问

  if (q->msg_num >= MAX_QUEUE_ENTRIES) { //如果队列已满 直接退出
  
    sys_mutex_unlock(&(q->mutex));	//退出前记得解锁
	//Printf("[Sys_arch]:mbox try post mbox full\n");
    return ERR_MEM;
  }

  q->q_mem[q->head] = msg;	//写入消息
  (q->head)++;	//调节写入指针
  if (q->head >= MAX_QUEUE_ENTRIES) {	//如果已经到队尾
    q->head = 0;	//从头开始
  }

  q->msg_num++;		//增加消息计数
  if(q->msg_num == MAX_QUEUE_ENTRIES)	//满队处理
  {
    //Printf("mbox try post, box full\n");
  }
  
  sys_sem_signal(&(q->sem));	//消息正常投递 释放信号量
  
  sys_mutex_unlock(&(q->mutex));	//解锁
  return ERR_OK;
}

/*
* 函数功能：从邮箱获取消息 如果timeout不为0 则表示等待的最大毫秒数，此时如果等待到消息
* 则返回等待时间（ms）；若timeout为0 表示函数阻塞等待，直到收到消息。
* 可能从邮箱中收到一条空消息，应用程序不会对这种消息做任何处理，直接丢弃。
**/
u32_t sys_arch_mbox_fetch(sys_mbox_t *q, void **msg, u32_t timeout)
{
  u8_t Err;
  u32_t wait_ticks;
  u32_t start, end;
  u32_t tmp_num;
  //SYS_ARCH_DECL_PROTECT(lev);

  // parameter check 
  LWIP_ASSERT("q != SYS_MBOX_NULL", q != SYS_MBOX_NULL);
  LWIP_ASSERT("q->sem != NULL", q->sem != NULL);
  
  wait_ticks = 0;
  if(timeout!=0){
	 wait_ticks = (timeout * OS_TICKS_PER_SEC)/1000;
	 if(wait_ticks < 1)
		wait_ticks = 1;
	 else if(wait_ticks > 65535)
			wait_ticks = 65535;
  }
  /* 阻塞信号量 直到邮箱中有数据或超时*/
  start = sys_arch_sem_wait(&(q->sem), timeout);
  //end = sys_now();

  if (start != SYS_ARCH_TIMEOUT)	//如果成功获取了信号量
  {
    //SYS_ARCH_PROTECT(lev);
    sys_mutex_lock(&(q->mutex));	//获取缓冲区的访问锁
	
	if(q->head == q->tail)	//如果头尾相等  返回错误
	{
     //   Printf("mbox fetch queue abnormal [%u]\n", q->msg_num);
		if(msg != NULL) {
			*msg  = NULL;
	    }
		//SYS_ARCH_UNPROTECT(lev);
		sys_mutex_unlock(&(q->mutex));
		return SYS_ARCH_TIMEOUT;
	}
	
    if(msg != NULL) {	//如果传入的指针 有效
      *msg  = q->q_mem[q->tail];	//从尾部读取数据
    }

    (q->tail)++;	//调制读数据指针
    if (q->tail >= MAX_QUEUE_ENTRIES) {	//如果已经读到尾部
      q->tail = 0;	//从头开始再读
    }

	if(q->msg_num > 0)	//减少邮箱中的消息数
	{
      q->msg_num--;
	}
	else
	{
      //Printf("mbox fetch queue error [%u]\n", q->msg_num);
	}

	tmp_num = (q->head >= q->tail)?(q->head - q->tail):(MAX_QUEUE_ENTRIES + q->head - q->tail);

	if(tmp_num != q->msg_num)
	{
       // Printf("mbox fetch error, umatch [%u] with tmp [%u]\n", q->msg_num, tmp_num);
	}
	
	//SYS_ARCH_UNPROTECT(lev);
	sys_mutex_unlock(&(q->mutex)); //释放访问权
	//Printf("mbox fetch ok, match [%u] with tmp [%u] \n", q->msg_num, tmp_num);
	//return (u32_t)(end - start);		//将等待时间设置为timeout/2;
	return start;
  }
  else	//获取信号量超时
  {
    //Printf("mbox fetch time out error");
    if(msg != NULL) {
      *msg  = NULL;	//返回空
    }
	
	return SYS_ARCH_TIMEOUT;	//返回超时错误
  }
}
/*
* 函数功能：尝试从邮箱中读取消息，该函数不会阻塞进程 当邮箱中有数据时切读取成功
* 返回0 否则立即返回SYS_MOBX_EMPTY
*****/
u32_t sys_arch_mbox_tryfetch(sys_mbox_t *q, void **msg)
{
  u32_t tmp_num;
  //SYS_ARCH_DECL_PROTECT(lev);
  u32_t start;
  /* parameter check */
  LWIP_ASSERT("q != SYS_MBOX_NULL", q != SYS_MBOX_NULL);
  LWIP_ASSERT("q->sem != NULL", q->sem != NULL);

  if(q->msg_num == 0)	//如果消息数据为0
  	return SYS_MBOX_EMPTY;
  /* 等待信号量 时间上限为1ms */
  start = sys_arch_sem_wait(&(q->sem), 1);
  
  if (start != SYS_ARCH_TIMEOUT) {	//如果成功获取了信号量
    //SYS_ARCH_PROTECT(lev);
    sys_mutex_lock(&(q->mutex));	//申请缓冲区的访问权
	if(q->head == q->tail)	
	{
       // Printf("mbox tryfetch queue abnormal [%u]\n", q->msg_num);
		if(msg != NULL) {
			*msg  = NULL;
	    }
		//SYS_ARCH_UNPROTECT(lev);
		sys_mutex_unlock(&(q->mutex));
		return SYS_MBOX_EMPTY;
	}
		
    if(msg != NULL) {	//读取消息
      *msg  = q->q_mem[q->tail];
    }

    (q->tail)++;	//调整数据指针
    if (q->tail >= MAX_QUEUE_ENTRIES) {
      q->tail = 0;
    }

    if(q->msg_num > 0)	//减少邮箱中的消息数
	{
      q->msg_num--;
	}

	tmp_num = (q->head >= q->tail)?(q->head - q->tail):(MAX_QUEUE_ENTRIES + q->head - q->tail);
    
	
	if(tmp_num != q->msg_num)
	{
        Printf("mbox try fetch error, umatch [%u] with tmp [%u]\n", q->msg_num, tmp_num);
	}
	
    //SYS_ARCH_UNPROTECT(lev);
    sys_mutex_unlock(&(q->mutex));	//释放访问控制权
    return 0;
  }
  else	//获取信号量超时
  {
   // Printf("mbox try fetch uknow error\n");
    if(msg != NULL) {
      *msg  = NULL;	//返回空
    }

    return SYS_MBOX_EMPTY;	//返回邮箱为空
  }
}

/*
* 函数功能：新建一个进程，在整个系统中只会被调用一次
* name：进程名字 thread：进程函数 arg：创建进程时的参数 stacksize：进程堆栈空间 prio：进程优先级
*/
sys_thread_t sys_thread_new(const char *name, lwip_thread_fn thread, void *arg, int stacksize, int prio)
{
  static u32_t TaskCreateFlag=0;
  u8_t i=0;
  name=name;
  stacksize=stacksize;
  /* 为任务寻找堆栈空间 */
  while((TaskCreateFlag>>i)&0x01){
    if(i<LWIP_MAX_TASKS&&i<32)
          i++;
    else return 0;
  }
  if(OSTaskCreate(thread, (void *)arg, &LWIP_STK_AREA[i][LWIP_STK_SIZE-1],prio)==OS_NO_ERR){
       TaskCreateFlag |=(0x01<<i); //设置堆栈使用标志
	   
  };

  return prio; //返回进程优先级号作为进程编号
}

#endif



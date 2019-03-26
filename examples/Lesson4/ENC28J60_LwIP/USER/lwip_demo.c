#include "lwip_demo.h"
#include "sys.h"


//定义一个网络接口结构
struct netif enc28j60_netif;
static void lwip_early_init()
{
    struct ip_addr ipaddr, netmask, gw;
    
    lwip_init();
    IP4_ADDR(&gw, 192,168,12,1);
    IP4_ADDR(&netmask, 255,255,255,0);
    IP4_ADDR(&ipaddr, 192,168,12,14);
    
    netif_add(&enc28j60_netif, &ipaddr, &netmask, &gw, NULL, ethernetif_init, ethernet_input);
    netif_set_default(&enc28j60_netif);
    netif_set_up(&enc28j60_netif);
    
}


void lwip_demo(void)
{
	//init LwIP
	lwip_early_init();

	//for periodic handle
	while(1)
	{
		
		
		//process LwIP timeout
		sys_check_timeouts();
		
		//todo: add your own user code here
        GPIO_ToggleBits(GPIOB, GPIO_Pin_4);
	}
}

//外部中断4服务程序
void EXTI4_IRQHandler(void)
{
    if(EXTI_GetITStatus(EXTI_Line4) != RESET)
    {
         process_mac();
         EXTI_ClearITPendingBit(EXTI_Line4);//清除LINE4上的中断标志位  
    }
}











#include "sys.h"
#include "delay.h"
#include "usart.h"
#include "led.h"
#include "enc28j60.h"
#include "timer.h"
#include "lwip_demo.h"
#include "oled.h"

int main(void)
{ 
 
	delay_init(168);		  //初始化延时函数
    uart_init(115200);
	LED_Init();		        //初始化LED端口
    TIM3_Int_Init(2000-1, 84-1);  // 20ms中断一次
    OLED_Init();
    OLED_ShowString(0,0, "  LwIP DEMO", 16);
    lwip_demo();
    
    return 0;
}


	

 




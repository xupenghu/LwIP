#include "sys.h"
#include "delay.h"
#include "usart.h"
#include "led.h"

#include "stdlib.h"
#include "oled.h" 

int main(void)
{ 
 
	delay_init(168);		  //初始化延时函数
	LED_Init();		        //初始化LED端口
	OLED_Init();			//初始化OLED  
	OLED_Clear();
	OLED_ShowString(0,0,"0.96' OLED TEST",16);
	
    while(1)
    {
        LED2 = 0;
        LED3 = 1;
        delay_ms(500);
        LED2 = 1;
        LED3 = 0;
        delay_ms(500);
     }
}


	

 




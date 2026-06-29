


#include	<unistd.h>
#include	<glib.h>
#include	"lin_if.h"
#include        <termios.h>
#include        <termios.h>
#include 	<time.h>
#include	<sys/timerfd.h>

#include  <fcntl.h>
#include  <errno.h>
#include <sys/stat.h>
#include <stdio.h>


#define FALSE 0
#define TRUE  1

int lin_fd;

struct T_GPIO_context   GPIO_PIN;
struct T_GPIO_context   GPIO_PIN1;

GIOChannel *lin_channel;
guint LIN_watch_id;

lin_UARTContext *Global_lin_context = NULL;


/************************************************************************************************************
 Function name             : LIN_rx_callback()
 Function Parameters type  : GIOChannel, GIOCondition, gpointer
 Short Description         : Function handles LIN RX interrupt call back
                             Glib invokes the LIN_rx_callback when Lin RX triggered
 Return                    : True
*************************************************************************************************************/
gboolean LIN_rx_callback(GIOChannel *source, GIOCondition condition, gpointer data)
{

        if(condition & G_IO_IN)
        {
		char test[8];
		GIOStatus status ;
		gsize read_byte;
		GError *error = NULL;
                status = g_io_channel_read_chars(source, test ,8, &read_byte,&error);

		printf("received LIN buffer%s",test);
			
	}
	 /*If there is UART failure */
        else {
                /* Do nothing */
        }

        return TRUE;
}


int lin_init(void)
{
	

	const char *uart_dev = "/dev/ttyS3"; 
	struct termios options;
	uint8_t send_data[8] = {0xAA, 0x55, 0xF0, 0x0F, 0xAA, 0x55, 0xF0, 0x0F};
	char test[] = "GowthamS";
	char test1[8];
	int identifier = 0x3C;
	int iter = 0;
	unsigned int id;
	unsigned int inputvalue;
	lin_fd = open(uart_dev, O_RDWR);
	if (lin_fd < 0) {
        	perror("UART open failed");
        	return 1;
	
	}

#if 0
	ioctl(fd,ATMEL_IOCTL_RAW_mode,NULL);


        close(fd);

        fd = open(uart_dev, O_RDWR);
        if (fd < 0) {
                perror("UART open failed");
                return 1;

        }


        ioctl(fd,ATMEL_IOCTL_RAW_mode,NULL);

#endif
#if 0
        tcgetattr(fd, &options);


	options.c_iflag = 0;
	options.c_oflag = 0;
	options.c_lflag = 0;


        options.c_cflag |= (CLOCAL | CREAD);
        options.c_iflag &= ~(IXON | IXOFF | IXANY);

        options.c_cflag &= ~(CSIZE | PARENB | CSTOPB | CRTSCTS);
        options.c_cflag |= (CS8 | CREAD | CLOCAL);

	options.c_cc[VTIME] = 1; // read timeout 10*100ms
	options.c_cc[VMIN] = 0;

	cfsetispeed(&options, B115200);
	cfsetospeed(&options, B115200);
	tcflush(fd, TCIFLUSH);
	tcsetattr(fd, TCSANOW, &options);

#endif

	GPIO_PIN.gpio_number = 82;
        GPIO_PIN.direction = GPIO_DIRECTION_OUT;

        T_gpio_PIN_config(&GPIO_PIN);

        T_gpio_PIN_set(&GPIO_PIN, 1);
/*	
	GPIO_PIN1.gpio_number = 85;
        GPIO_PIN1.direction = GPIO_DIRECTION_OUT;

        T_gpio_PIN_config(&GPIO_PIN1);

        T_gpio_PIN_set(&GPIO_PIN1, 1);
*/
/*
	lin_channel = g_io_channel_unix_new(lin_fd);
        g_io_channel_set_encoding(lin_channel, NULL, NULL); // Binary mode
        g_io_channel_set_flags(lin_channel,  G_IO_FLAG_NONBLOCK, NULL);
     
        g_io_channel_set_buffered(lin_channel, FALSE);              // <- important
        g_io_channel_set_close_on_unref(lin_channel, TRUE); 
        Global_lin_context = g_new(lin_UARTContext ,1); 
        Global_lin_context->lin_channel = lin_channel;

        LIN_watch_id = g_io_add_watch(lin_channel, G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_PRI | G_IO_NVAL, LIN_rx_callback, Global_lin_context);


*/
	inputvalue = 9600;
	ioctl(lin_fd, ATMEL_IOCTL_SET_LIN_BAUD, &inputvalue);
	sleep(1);


#if 1

	printf("Master\n");
	sleep(1);
	ioctl(lin_fd, ATMEL_IOCTL_SET_MODE, NULL);

	id = 0x3C;

	sleep(1);

//	ioctl(lin_fd, ATMEL_IOCTL_SET_LIN_ID, &id);
	
//	usleep(500);



//	ioctl(lin_fd, ATMEL_IOCTL_ENABLE_LIN_SEND_DATA,NULL);

	ioctl(lin_fd, ATMEL_IOCTL_SET_LIN_ID, &id);
//	write(lin_fd, send_data,8);
//	usleep(5000);
/*	id = 0x3D;
	ioctl(lin_fd, ATMEL_IOCTL_SET_LIN_ID, &id);


	ioctl(lin_fd, ATMEL_IOCTL_CHECK_RX_READY, NULL);
*/
//	read(lin_fd, test1, sizeof(test1));
//`	printf("read = %s\n", test1);

#endif

#if 0

	printf("Slave\n");
	sleep(1);
	ioctl(lin_fd, ATMEL_IOCTL_CHECK_SLAVE_MODE, NULL);
	while(1)
	{
		ioctl(lin_fd, ATMEL_IOCTL_CHECK_SLAVE_RESPONSE, NULL);
	}

#endif

	sleep(5);
	printf("Done\n");

//	for(iter = 0;iter < 10; iter++)
	{
//		write(fd, test, 8);
	//	sleep(1);
//		ioctl(fd, ATMEL_IOCTL_SET_LIN_ID, &id);
//		sleep(1);

	}
	return 0;
	
}

int lin_deinit(void)
{
	
	return 0;
}


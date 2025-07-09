#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <linux/gpio.h>
#include <sys/ioctl.h>
#define DEV_GPIO "/dev/gpiochip0"

int main(int argc, char *argv[])
{
 int fd;
 int ret;
 struct gpiochip_info cinfo;
 struct gpioline_info linfo;
 struct gpiohandle_request req;
 struct gpiohandle_data data;
 /* open gpio */
 fd = open(DEV_GPIO, 0);
 if (fd < 0) {
 printf("ERROR: open %s ret=%d\n", DEV_GPIO, fd);
 return -1;
 }
 /* get gpio chip info */
 ret = ioctl(fd, GPIO_GET_CHIPINFO_IOCTL, &cinfo);
 if (ret < 0) {
 printf("ERROR get chip info ret=%d\n", ret);
 return -1;
 }
 printf("GPIO chip: %s, \"%s\", %u GPIO lines\n",
 cinfo.name, cinfo.label, cinfo.lines);
 ret = ioctl(fd, GPIO_GET_LINEINFO_IOCTL, &linfo);
 if (ret < 0) {
 printf("ERROR get line info ret=%d\n", ret);
 return -1;
 }
 printf("line %2d: %s\n", linfo.line_offset,
 linfo.name);
 /* set gpio_pb2 output */

// 128 gpio in gpiochip0
 // 0 ~ 31 PA0 -> PA31
 // 32 ~ 63 PB0 -> PB31
 // 33 ~ 95 PC0 -> PC31
 // 96 ~ 127 PD0 -> PD31

req.lineoffsets[0] = 34;
 req.lines = 1;
 req.flags = GPIOHANDLE_REQUEST_OUTPUT;
 strcpy(req.consumer_label, "RST_mBUS1");
int lhfd = ioctl(fd, GPIO_GET_LINEHANDLE_IOCTL, &req);
 if (lhfd < 0) {
 printf("ERROR get line handle lhdf=%d\n", lhfd);
 return -1;
 }
 data.values[0] = 1;
 ret = ioctl(req.fd, GPIOHANDLE_SET_LINE_VALUES_IOCTL, &data);
 if (ret < 0) {
 printf("ERROR set line value ret=%d\n", ret);
 return -1;
 }
 while (1) {

// set gpio_pb2 low
 data.values[0] = 0;
 ioctl(req.fd, GPIOHANDLE_SET_LINE_VALUES_IOCTL, &data);
 usleep(5*1000);

// set gpio_pb2 high
 data.values[0] = 1;
 ioctl(req.fd, GPIOHANDLE_SET_LINE_VALUES_IOCTL, &data);
 usleep(5*1000);
 }
 /* close gpio */
 close(fd);
 return 0;
}

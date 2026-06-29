#ifndef _LIN_IF_H_
#define	_LIN_IF_H_

#include	<glib.h>
#include	"g3d.h"
#include        "hfcp.h"
#include        "ioctl_common.h"


typedef struct {

        GIOChannel *lin_channel;
}lin_UARTContext;

extern int lin_init(void);
extern int lin_deinit(void);

#endif /* _CAN_IF_H_ */


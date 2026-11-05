#include <stddef.h>
#include <linux/usbdevice_fs.h>
#include <sys/ioctl.h>
_Static_assert(sizeof(struct usbdevfs_ctrltransfer) == 24, "control ABI");
_Static_assert(offsetof(struct usbdevfs_ctrltransfer, data) == 16, "pointer offset");
_Static_assert(sizeof(struct usbdevfs_bulktransfer) == 24, "bulk ABI");
_Static_assert(sizeof(struct usbdevfs_disconnect_claim) == 264, "disconnect ABI");
_Static_assert(USBDEVFS_CONTROL == 0xC0185500UL, "control ioctl");
_Static_assert(USBDEVFS_BULK == 0xC0185502UL, "bulk ioctl");
_Static_assert(USBDEVFS_CLAIMINTERFACE == 0x8004550FUL, "claim ioctl");
_Static_assert(USBDEVFS_RELEASEINTERFACE == 0x80045510UL, "release ioctl");
_Static_assert(USBDEVFS_DISCONNECT_CLAIM == 0x8108551BUL, "disconnect ioctl");

_Static_assert(sizeof(struct usbdevfs_getdriver) == 260, "getdriver ABI");
_Static_assert(USBDEVFS_GETDRIVER == 0x41045508UL, "getdriver ioctl");
_Static_assert(USBDEVFS_DISCONNECT_CLAIM_IF_DRIVER == 1, "conditional detach flag");
_Static_assert(USBDEVFS_SETCONFIGURATION == 0x80045505UL, "set configuration ioctl");
_Static_assert(sizeof(struct usbdevfs_setinterface) == 8, "alternate setting ABI");
_Static_assert(USBDEVFS_SETINTERFACE == 0x80085504UL, "set interface ioctl");

#ifndef KERNEL_SUPPLEMENT_H
#define KERNEL_SUPPLEMENT_H

/*
This file is parsed only when building from Kernel source.
Include here headers containing structures for which you'd
like to generate binding for, not included in the other header files.
*/

#include <linux/fs_struct.h> // expose fs_struct

#endif

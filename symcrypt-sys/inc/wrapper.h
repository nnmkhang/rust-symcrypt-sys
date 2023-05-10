#ifdef __linux__ 
#include <stddef.h>
#endif

#include "symcrypt.h"
//I see. In that case, you can either modify symcrypt.h or symcrypt_internal.h to
// include stddef.h, or create another file that wraps those ones

//https://github.com/dankamongmen/notcurses/issues/856
/* Waits for a pid that has not been created. */

#include <syscall.h>
#include "tests/main.h"

void test_main(void) { wait((pid_t)123); }

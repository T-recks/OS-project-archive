/* Ensure that the executable of a running process cannot be
   modified. */

#include <syscall.h>
#include "tests/lib.h"
#include "tests/main.h"

void test_main(void) {
  int handle;
  char buffer[16];

  wait(exec("do-nothing"));
  CHECK((handle = open("do-nothing")) > 1, "open \"do-nothing\"");
  CHECK(read(handle, buffer, sizeof buffer) == (int)sizeof buffer, "read \"do-nothing\"");
  CHECK(write(handle, buffer, sizeof buffer) == 16, "try to write \"do-nothing\"");
}

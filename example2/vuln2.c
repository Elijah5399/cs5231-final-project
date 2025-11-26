#include <stdio.h>
#include <unistd.h>

int win() {
  printf("Hello!\n");
  system("/bin/sh");
}

int main() {
  char buf[32];
  gets(buf); // can try to change this with other lib/syscalls
  printf("%s\n", buf);
  return 0;
}

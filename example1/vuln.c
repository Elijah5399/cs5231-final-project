#include <stdio.h>
#include <unistd.h>

int win() {
  execve("/bin/sh", NULL, NULL);
}

int main() {
  char buf[32];
  gets(buf); // can try to change this with other lib/syscalls
  printf("%s\n", buf);
  return 0;
}

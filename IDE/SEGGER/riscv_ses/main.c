/*
File    : main.c
Purpose : Generic application start
*/

#include <stdio.h>
#include <stdlib.h>

void check(int depth) {
    char ch;
    char *ptr = malloc(1);

    printf("stack at %p, heap at %p\n", &ch, ptr);
    if (depth <= 0)
        return;

    check(depth-1);
    free(ptr);
}
/*********************************************************************
*
*       main()
*
*  Function description
*   Application entry point.
*/

void main(void) {
  int i;
  char c[0x1000]; /* testing stack*/

  check(10); /* testing stack and heap addresses*/
  for (i = 0; i < 100; i++) {
    printf("Hello World %d!\n", i);
  }
  do {
    i++;
  } while (1);
}

/*************************** End of file ****************************/

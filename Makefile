CFLAGS = -O2 -Wall -Wextra -Werror -std=gnu11 -pedantic -pedantic-errors -g

all: measure testprog

measure: measure.c
	$(CC) $(CFLAGS) -o $@ $< 

testprog: testprog.c
	$(CC) -O0 -static -o $@ $< 

clean:
	rm -f measure testprog

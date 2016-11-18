CFLAGS = -O2 -Wall -Wextra -Werror -std=gnu11 -pedantic -pedantic-errors -g

measure: measure.c
	$(CC) $(CFLAGS) -o $@ $< 

clean:
	rm -f measure

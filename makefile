CC = gcc
CFLAGS = -g -Wall

cbc_test: cbc_test.c modes.o aes.o
	$(CC) $(CFLAGS) $^ -o $@

htest: htest.c aes.o
	$(CC) $(CFLAGS) $^ -o $@

modes.o: modes.c modes.h aes.o
	$(CC) $(CFLAGS) -c $^

aes.o: aes.c aes.h
	$(CC) $(CFLAGS) -c $^

clean:
	rm *.o *~


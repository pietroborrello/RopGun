all:
	gcc -O3 qkiller.c -o qkiller -pthread

clean:
	-rm qkiller.o qkiller
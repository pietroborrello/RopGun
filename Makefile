all:
	gcc -O3 qkiller.c syscallnames.c -o qkiller -pthread

clean:
	-rm qkiller
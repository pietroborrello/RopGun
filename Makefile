all:
	gcc -O3 ropgun.c syscallnames.c -o ropgun -pthread

clean:
	-rm ropgun
all:
	gcc -O3 ropgun.c syscallnames.c -o ropgun -pthread

install:
	cp ropgun /usr/local/bin
	chmod 0755 /usr/local/bin/ropgun

clean:
	-rm ropgun
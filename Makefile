bwsniff : bwsniff.c
	cc  bwsniff.c -lpcap -lncurses -lpthread -o bwsniff

clean :
	rm -f bwsniff
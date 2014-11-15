all: librm64

#make file della librearia statica librm64, per adesso include solamente il file rm_start.c in src
#gli inserisco come include la cartella ./include, poiche ha bisogno degli header di distorm3
#ho inserito anche gli include per glib
librm64:
	gcc -c -D RM_DEBUG=1 ./src/rm_start.c -I./include/ -I/usr/include/glib-2.0 -I/usr/lib/x86_64-linux-gnu/glib-2.0/include
	ar rcs ./lib/librm64.a ./rm_start.o

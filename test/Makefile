LIB = -L../lib -lrm64 -ldistorm3 -lelf -lglib-2.0
INC = -I../include


all: test



test:
	gcc -O0 -D DEBUG=1 ./test.c -o ../bin/test $(INC) $(LIB)
#in questo modo compilo test.c generando l'eseguibile test.out, passando la macro DEBUG=1, avendo messo -lrm64 come libreria
#che si trova in ../lib ed avendogli indicato come direttorio per gli include ../include


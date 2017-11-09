CC = gcc
LIBS = -lpcap

all: mydump 
mydump: mydump.o 
	${CC} ${FLAGS} -o mydump mydump.o ${LIBS}
mydump.o: mydump.c
	${CC} ${FLAGS} -c mydump.c myStruct.h

clean:
	rm mydump.o mydump *.gch



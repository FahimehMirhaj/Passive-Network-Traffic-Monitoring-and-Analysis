# build an executable named mydump from mydump.c

all: mydump.c
	gcc mydump.c -o mydump -lpcap
clean:
	$(RM) mydump

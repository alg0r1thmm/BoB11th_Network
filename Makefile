#Makafile
all: add-nbo
	@echo -n -e \\x00\\x00\\x03\\xe8 > thousand.bin
	@echo -n -e \\x00\\x00\\x01\\xf4 > five-hundred.bin

add-nbo: add-nbo.c
	gcc -o add-nbo add-nbo.c

clean:
	rm -f *.o

#Makafile
all: add-nbo

add-nbo: add-nbo.c
	gcc -o add-nbo add-nbo.c

echo -n -e \\x00\\x00\\x03\\xe8 > thousand.bin
echo -n -e \\x00\\x00\\x01\\xf4 > five-hundred.bin


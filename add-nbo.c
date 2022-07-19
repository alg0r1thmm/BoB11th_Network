#include <stdio.h>
#include <stdint.h>
#include <netinet/in.h>

int main(void)
{
    printf("\nsyntax : add-nbo <file1> <file2>\n");
    printf("sample : add-nbo a.bin c.bin\n\n");
    printf("# example\n");
    printf("echo -n -e \\x00\\x00\\x03\\xe8 > thousand.bin \n");
    printf("echo -n -e \\x00\\x00\\x01\\xf4 > five-hundred.bin \n\n\n");

    FILE* file1 = NULL;
    FILE* file2 = NULL;

    uint32_t bin_value1;
    uint32_t bin_value2;
    uint32_t result_value;
   
    file1 = fopen("thousand.bin", "r");
    file2 = fopen("five-hundred.bin","r");

    int binary_1 = fread(&bin_value1, sizeof(uint32_t), 1, file1);
    int bianry_2 = fread(&bin_value2, sizeof(uint32_t), 1, file2);

    bin_value1 = ntohl(bin_value1);
    bin_value2 = ntohl(bin_value2);
    result_value = bin_value1 + bin_value2;

    printf("./add-nbo thousand.bin five-hundred.bin\n");

    printf("%d(0x%x) + %d(0x%x) = %d(0x%x)\n\n",bin_value1, bin_value1, bin_value2, bin_value2, result_value, result_value);

    return 0;
}
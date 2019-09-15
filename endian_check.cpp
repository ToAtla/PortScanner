
#include <stdio.h>
#include <iostream>

/* function to show bytes in memory, from location start to start+n*/
void show_mem_rep(char *start, int n)
{
    int i;
    for (i = 0; i < n; i++)
        printf(" %.2x", start[i]);
    printf("\n");
}

/*Main function to call above function for 0x01234567*/
int main()
{
    int i = 0x01234567;
    show_mem_rep((char *)&i, sizeof(i));
    int x = 1;
    if (*(char *)&x)
    {
        std::cout << "Little Endian" << std::endl;
    }
    else
    {
        std::cout << "Big Endian" << std::endl;
    }
    return 0;
}

/*
When above program is run
on little endian machine, gives “67 45 23 01” as output ,
while if it is run on big endian machine, gives “01 23 45 67” as output.
*/

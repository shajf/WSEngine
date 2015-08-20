/*
 * =====================================================================================
 *      Copyright (C) 2014 jianfeng sha
 *
 *      Filename:  test_hash.c
 *
 *      Description:  
 *
 *      Created:  11/18/14 10:11:24
 *
 *      Author:  jianfeng sha , csp001314@163.com
 *
 * =====================================================================================
 */

#include <stdio.h>

static size_t str_hash(char *str)
{
    size_t hash = 0; 
    size_t  x = 0;
    
    while (*str)
    {
        hash = (hash << 4) + (*str++);  
        if ((x = hash & 0xF0000000L) != 0)
        {
            hash ^= (x >> 24);
            hash &= ~x;
        }
    }
    return (hash & 0x7FFFFFFF);
}

static void test_columns(const char **columns){
    
    int i=0;
    while(columns[i]){
	printf("%s\n",columns[i++]);
    }
}

int main(int argc,char** argv){
    const char * columns[4] = {"a","b","c",NULL};

    printf("%d,%d\n",str_hash(argv[1]),str_hash(argv[1])%64);
    test_columns(columns);
}



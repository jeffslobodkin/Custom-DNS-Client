// Jeffrey Slobodkin
// CSCE 463 Fall 2024
// UIN: 532002090

#include "pch.h"
#include <iostream>

int main(int argc, char* argv[])
{
    if (argc != 3) {
        printf("The program must contain two arguments but has %d", argc);
        exit(-1);
    }



    Socket sock = Socket(argv[1], argv[2]);

    sock.Bind();
    sock.CreateBuffer();
    sock.Send();


    return 0;


}
 

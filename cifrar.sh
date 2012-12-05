#!/bin/sh -v
./iarsac -c Alicia < mi_texto_plano.txt | uuencode - >  mi_texto_cifrado.txt

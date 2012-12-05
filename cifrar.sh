#!/bin/sh -v
# Este script cifra un texto (como ejemplo de texto a cifrar usa la 
# documentacion de iarsac)
./iarsac -c Alicia < iarsac-doc.tex | uuencode - >  mi_texto_cifrado.txt

all:	iarsac 

iarsac:	iarsac.cpp
	g++ iarsac.cpp  -Wall -g -lntl -lgmp -lm -o iarsac

clean:   
	rm iarsac
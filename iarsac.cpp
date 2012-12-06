// IARSAC - Versión 0.3
// Implementación del Algoritmo RSA en C++ 
//
// Copyright (C) 2003-4 Pablo De Napoli
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

// ChangeLog

// 0.1- initial release
// 0.2- cast to unsigned char* to fix compilation warnings 
// change of the encrypted format: add a length for each block
// to avoid problems with the size of the last block
// 0.3 - error messages if problems when reading public/private keys
// support for multiple users

// Usamos la libreria NTL para numeros de gran tamaño
// ZZ es la clase de NTL para enteros de gran tamaño

#include <NTL/ZZ.h>
using namespace NTL;

// Usamos la clase string de la libreria standard

using namespace std;
#include <string>

// y la clase ifstream para leer /dev/random

#include <fstream>

#include <getopt.h>
#include <assert.h>


// Variables Globales

long longitud_de_clave=100;
string usuario;

enum {no_valida,show_help,generar_claves,cifrar,descifrar,show_license};
// la accion no_valida es cero

bool verbose=0;

class encriptador_rsa
{

public:
  
  void generar_claves(long longitud);
  
  void cifrar(istream& texto_plano,ostream& texto_encriptado);

  void descifrar(istream& texto_encriptado,ostream& texto_plano);
  
  void establecer_parametros(); 
 
  ZZ n;
  ZZ clave_publica;
  ZZ clave_privada;
 
private: 

  // n sera el tamaño del "alfabeto" en el cual vamos a cifrar o
  // descifrar

  long longitud_de_clave;
  long long_bloque_plano;
  long long_bloque_encriptado;
 
};

void encriptador_rsa::generar_claves(long longitud)
{
 
  ZZ p;
  ZZ q;
  ZZ phi_n;

 // Elegimos (al azar) dos números primos (grandes) distintos
 // ZZ es el tipo de datos "entero grande" de la libreria NTL
 
 p = GenPrime_ZZ(longitud);
 do 
 {
  q = GenPrime_ZZ(longitud);}
 while (p==q);

 n = p*q;
 phi_n = (p-1)*(q-1);
 
 if (verbose)
 {
 cerr << "Generando claves RSA para " << usuario << "\n";
 cerr << "longitud de clave=" << longitud << " bits \n";
 cerr << "Primos elegidos \n";
 cerr << "p=" << p << "\n";
 cerr << "q=" << q << "\n";
 };

 // la clave privada debe ser un numero (al azar) que no tenga factores
 // en comun con (p-1)*(q-1)
 
 do {
	 clave_publica = RandomLen_ZZ(longitud)%n;
 } while (GCD(clave_publica,phi_n)!=1);

 // la clave publica es el inverso modulo phi_n de la clave publica
 
 if (verbose)
 {
 cerr << "clave_publica=" << clave_publica << "\n";
 cerr << "n=" << n << "\n";
 cerr << "phi_n=" << phi_n << "\n";
 };

 clave_privada = InvMod(clave_publica,phi_n);  

 if (verbose)
 cerr << "clave_privada=" << clave_privada << "\n";

}

void encriptador_rsa::cifrar(istream& texto_plano,ostream& texto_encriptado)
{
 ZZ numero_plano,numero_encriptado;
 char* bloque_plano      = new char[long_bloque_plano+1];  // 1 para un cero al final
 char* bloque_encriptado = new char[long_bloque_encriptado+1];
 long input_count = 0;
 long output_count =0;
 
 while (1)
  {  
       texto_plano.read(bloque_plano,long_bloque_plano);
       int count=texto_plano.gcount(); // cuantos bytes fueron leidos
       input_count = input_count + count;
       if (count==0) break;

       // escribe una cabecera de bloque conteniendo la longitud 
       // del bloque a convertir

       if (verbose)
	   cerr << "long. de bloque plano=" << count <<"\n";
       texto_encriptado.write((char*)&count,sizeof(count));

       // completa el bloque con ceros para que tenga exactamente
       // long_bloque_plano bytes y pone un cero al final (para que
       // sea un C-string valido)
 
       char* p = bloque_plano + count;
       while (count <= long_bloque_plano)
       {
          *p = '\0'; 
          count++;
          p++;
       };

       if (verbose) cerr << "Bloque a convertir= \"" << bloque_plano << "\"\n";
       numero_plano = ZZFromBytes((unsigned char*) bloque_plano,long_bloque_plano);
       if (verbose) cerr << "convertido a numero= " << numero_plano << "\n";
       
       // Esta linea encripta
       numero_encriptado = PowerMod(numero_plano,clave_publica,n);
       
       if (verbose) cerr << "numero encriptado= " << numero_encriptado << "\n";
       BytesFromZZ((unsigned char*)bloque_encriptado,numero_encriptado,long_bloque_encriptado);
       *(bloque_encriptado+long_bloque_encriptado)='\0';
       if (verbose) cerr << "bloque encriptado= \"" << bloque_encriptado << "\"\n";
       
       texto_encriptado.write(bloque_encriptado,long_bloque_encriptado);
       output_count = output_count + long_bloque_encriptado; 	
   };
   if (verbose) 
   {
	cerr << "total de bytes leidos (texto plano)= "<< input_count << " \n";
        cerr << "total de bytes escritos (texto encriptado)=" << output_count << "\n"; 
   };
   delete bloque_plano;
   delete bloque_encriptado;
}

void encriptador_rsa::descifrar(istream& texto_encriptado,ostream& texto_plano)
{
 ZZ numero_plano,numero_encriptado;
 char* bloque_plano      = new char[long_bloque_plano+1];  // 1 para un cero al final
 char* bloque_encriptado = new char[long_bloque_encriptado+1];
 long input_count = 0;
 long output_count =0;
 int count_from_file;
 
 while (1)
  {  
       // lee la cabecera de bloque: cuantos bytes de texto plano componen el
       // bloque?

       texto_encriptado.read((char*)&count_from_file,sizeof(count_from_file));
       if (verbose)
	  cerr << "long bloque plano from file=" << count_from_file;
       
       // Ahora leemos el bloque

       texto_encriptado.read(bloque_encriptado,long_bloque_encriptado);
       int count=texto_encriptado.gcount(); // cuantos bytes fueron leidos
       if (count ==0) break;
       input_count = input_count + count;
       if (count < long_bloque_encriptado)
       {
           cerr << "count=" << count << "\n";
           cerr << "Error al leer el archivo encriptado!\n";
           abort();
       }; 
 
       // pone un cero al final (para que sea un C-string valido)
 
       *(bloque_plano+long_bloque_plano)='\0';
       if (verbose) cerr << "Bloque a descifrar= \"" << bloque_encriptado << "\"\n";
       numero_encriptado = ZZFromBytes((unsigned char*)bloque_encriptado,long_bloque_encriptado);
       if (verbose) cerr << "convertido a numero= " << numero_encriptado << "\n";
       
       // Esta linea desencripta
       numero_plano = PowerMod(numero_encriptado,clave_privada,n);
       
       if (verbose) cerr << "numero plano= " << numero_plano << "\n";
       BytesFromZZ((unsigned char*)bloque_plano,numero_plano,long_bloque_plano);
       *(bloque_plano+count_from_file)='\0';
       if (verbose) cerr << "bloque plano= \"" << bloque_plano << "\"\n";	
       texto_plano.write(bloque_plano,count_from_file);
       output_count = output_count + count_from_file; 	
   };
   if (verbose) 
   {
	cerr << "total de bytes leidos (texto encriptado)= "<< input_count << " \n";
        cerr << "total de bytes escritos (texto plano)=" << output_count << "\n"; 
   };
   delete bloque_plano;
   delete bloque_encriptado;
};

void encriptador_rsa::establecer_parametros()
{
  long_bloque_plano = NumBytes(n)-1;
  long_bloque_encriptado = NumBytes(n);
  if (verbose)
  {
    cerr << "bloque_encriptado=" << long_bloque_encriptado << '\n';
    cerr << "bloque_plano=" << long_bloque_plano << '\n';
  }
};

int parse_command_line(int argc,char** argv)
{
  static struct option long_options[] =
  {
   { "cifrar-para", required_argument, 0,'c'},
   { "descifrar-para",required_argument,0,'d'},
   { "generar-claves-para",required_argument,0,'g'},
   { "verbose",no_argument,0,'v'},
   { "longitud-de-clave",required_argument,0,'l'},
   { "help",no_argument,0,'h'},
   { "license",no_argument,0,'L'},
   { 0, 0 , 0 , 0 }
  };
  int accion=0;
  int option_index=0;
  int c;
  while (1)
  {
  c = getopt_long(argc,argv,"c:d:g:vl:hL",long_options,&option_index); 
  if (c == -1)  break;
  switch(c)
  {
    case 'l':  if (optarg) longitud_de_clave=strtol(optarg,NULL,10);
               break;
    case 'v':  verbose = 1;
	       break;
    case 'g':  accion=accion?no_valida:generar_claves;
               if (optarg) usuario = optarg;	
	       break;
    case  'c': accion=accion?no_valida:cifrar;
	       if (optarg) usuario = optarg;
	       break;
    case 'd':  accion=accion?no_valida:descifrar;
	       if (optarg) usuario = optarg;	
	       break;
    case 'L':  accion=accion?no_valida:show_license;
	       break;
    case 'h':
    default:   accion=accion?no_valida:show_help;
  }
 };
 return accion;
}

// funcion que lee bytes de /dev/random y lo utiliza como semilla para
// generar numeros aleatorios

void random_seed()
{
  ifstream random;
  int longitud=5;
  char bytes_leidos[longitud];
  random.open("/dev/random");
  random.read(bytes_leidos,longitud);
  random.close();
  
  ZZ semilla = ZZFromBytes((unsigned char*)bytes_leidos,longitud);   
  SetSeed(semilla);
}

void mostrar_version()
{
  cerr << "IARSAC version 0.3 \n";
  cerr << "Implementacion en C++ del Algoritmo RSA \n";
  cerr << "(C) 2003-4 por Pablo De Napoli \n\n";
};

int main(int argc,char** argv)
{
  encriptador_rsa rsa;
  string nombre_de_archivo;

  int accion=parse_command_line(argc,argv);
  switch (accion)
  {
  case generar_claves:  {
                   random_seed();
   		   rsa.generar_claves(longitud_de_clave);
   		   ofstream of;
		   nombre_de_archivo = usuario + ".clave_publica"; 
   		   of.open(nombre_de_archivo.c_str());
   		   of << rsa.n << '\n';
   		   of << rsa.clave_publica << '\n';
   		   of.close();
		   nombre_de_archivo = usuario + ".clave_privada";
   		   of.open(nombre_de_archivo.c_str());
   		   of << rsa.n << '\n';
   		   of << rsa.clave_privada << '\n';
   		   of.close();
                   }; 
                   break;
  
  case cifrar:       {
                   ifstream f;
		   nombre_de_archivo = usuario + ".clave_publica";
                   f.open(nombre_de_archivo.c_str());
		   if (f.fail())
 		   {
		     cerr << "error leyendo la clave pública para " << usuario << "\n";
		     exit(1);		
		   };
                   f >> rsa.n;
                   f >> rsa.clave_publica;
                   f.close();
		   
                   rsa.establecer_parametros();
                   rsa.cifrar(cin,cout);
                   };
                   break;
                     

 case descifrar:     {
		   ifstream f;
		   nombre_de_archivo = usuario + ".clave_privada";
                   f.open(nombre_de_archivo.c_str());
		   if (f.fail())
 		   {
		     cerr << "error leyendo la clave privada para "<< usuario << "\n";
		     exit(1);		
		   };
                   f >> rsa.n;
                   f >> rsa.clave_privada;
                   f.close();
                   rsa.establecer_parametros();
                   rsa.descifrar(cin,cout);   
  		   };
                   break;
                    
 
case show_license: mostrar_version();
                   cerr << "IARSAC es Software Libre y usted puede redistribuirlo o modificarlo \n";
                   cerr << "libremente, bajo las condiciones establecidas en la Licencia Publica GNU. \n";
		   cerr << "(GNU General Public Licence), version 2 o posterior (a su eleccion). \n \n";
                   cerr << "IARSAC se distribuye con la esperanza de que sea util \npero sin ningun tipo de garantia. \n";
                   break;

 case no_valida:  cerr << "Opcion(es) no valida(s) \n";

 case show_help:
  default:	   mostrar_version();
                   cerr << "Opciones:\n";
    		   cerr << "-g --generar-claves-para usuario:   genera las claves pública y privada \n";
    		   cerr << "-c --cifrar-para usuario:  encripta \n";
                   cerr << "-d --descifrar-para usuario: desencripta \n";
                   cerr << "-h --help: muestra esta ayuda \n";
                   cerr << "-L --license: muestra información sobre la licencia GPL \n";
                   cerr << "-l --longitud-de-clave \n"; 
                   cerr << "-v --verbose \n";
  }; 
 }


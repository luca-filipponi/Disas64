/*



file di testi per tutte le prove
l'eseguibile della compilazione deve andare dentro bin tramite il make



*/




#include <stdio.h>
//includo l'header per rm64 con tutte i prototipi delle funzioni necessari
#include "rm64.h"
//per adesso uso malloc per allocare memoria
#include <stdlib.h>


void main(){


printf("Eseguibile test1\n");

//richiamo la funzione di rm_start

#ifdef DEBUG

	printf("Macro di debug definita\n");
#else
	printf("Macro di debug non definita\n");

#endif



#ifdef DEBUG

	printf("Calling initialization function\n");
#endif

	rm_init(2,5);





/*


faccio degli accessi in memoria, e tramite la funzione rm_init() vado a disassemblare il codice
del'eseguibile che viene generato da test.c, in modo tale da riuscire a trovare quali sono 
gli indirizzi in memoria di queste istruzioni, andando a generare un array o una tabella che mantiene gli indirizzi
di queste istruzioni, cosi quando un seghandler parte ed è stato generato perche si tocca una zona di memoria reattiva,
andando a vedere l'istruzione che l'ha generato, sono in grado di capire quale è stata l'istruzione per andare poi a modificare 
il basic block di quell'istruzione inserendo un longjump verso una patch che chiama l'handler di memoria reattiva


*/


//alloco memoria per un intero, a me nn interessa la zona di memoria dove l'intero e allocato
//ma dove si troveranno le istruzioni che faranno operazioni su questo intero
//per adesso uso malloc, ma dovrei usare rm64_malloc, cioè la primitiva di allocazione di memoria reattiva
int *a=malloc(sizeof(int));

*a=5;



}











/********


File iniziale, inseriasco codice per il dissemblamento



*********/





#include <stdio.h>
/* include per distorm, forse ci vuole anche mnemonic.h*/
#include "distorm.h"
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sysexits.h>
#include <fcntl.h>


/*Include di libelf*/
#include <libelf.h>
#include <gelf.h>

/*Include per glib*/
#include <glib.h>


//MACRO PER DISTORM	
#define MAX_INSTRUCTIONS 1000

//Variabili globali
extern char _etext;
GArray *jmp_array;
GArray *func_array;
//devo mettere le struct per i basic block, per branch e mov


/* ============================================================================
 *  _rm_error	DA SISTEMARE
 
void _rm_error(int code, char* format, ...) {
#if RM_DEBUG == 1
    printf("[rm ERROR] ");
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
#endif
    errno = code;
}

*/

/*=============================================================================
	compare_address()
===============================================================================*/


gint compareAddress(gconstpointer a, gconstpointer b) {
    unsigned int address_a = *(unsigned int*)a;
    unsigned int address_b = *(unsigned int*)b;
    if(address_a < address_b) return -1;
    else if(address_a > address_b) return 1;
    else return 0;  // if(address_a = address_b)
}










/*
===========================================================================================================
					rm_init()

funzione di inizializzazione per la memoria reattiva,per adesso mi limito a disassemblare il codice
dell'eseguibile che la chiama, per ottenere gli indirizzi di memoria dele sezioni di codice dell'eseguibile



===========================================================================================================
*/

void rm_init(){

#ifdef RM_DEBUG
	printf("Funzione di inizializzazione della memoria reattiva\n");
	
#else
	printf("Debug Macro not defined!!!");

#endif

//accedo all'eseguibile

//apertura dell'eseguibile in esecuzione, ne prendo il nome
	
 	int fd;                 // File Descriptor
    	char *base_ptr;         // ptr to our object in memory
    	FILE* f;
    	char file[256];
    	int i=0,j;

	//apro il file in esecuzione che è registrato nel proc file system
	f = fopen("/proc/self/cmdline", "r");
	    fscanf(f, "%c", &file[i]);
	    while (!feof(f) && file[i]!='\0') {
	        i++;
	        fscanf(f, "%c", &file[i]);
	    }
    	fclose(f);

#ifdef RM_DEBUG
	printf("Inizio funzione rm_init():\n");
	printf("Nome dell'eseguibile : %s \n",file);
#endif

	//variabili per l'analisi dell'elf

	Elf *elf;
	Elf64_Ehdr *elf_header= (Elf64_Ehdr *) base_ptr;   // point elf_header at our object in memory 
        char *k;
	GElf_Sym sym;	
	Elf_Scn *scn;		    // section descriptor per l'iterazione
	GElf_Shdr shdr;             // Section Header
	Elf_Data *edata;    	    // data descriptor
        Elf_Kind ek; //usato per vedere che tipo di elf è
	char *basepointer; //puntatore alla zona di memoria dove copierò l'elf
	struct stat elf_stats;
	int symbol_count;
	void* code_end = &_etext;
	int count=0;//usato per scorrere jmp_array

	//Creation of jmp_array, that contains all the address location of executable code
	jmp_array=g_array_new(FALSE,FALSE,sizeof(void*)); //8 byte each element, 64 bit address
	func_array=g_array_new(FALSE,FALSE,sizeof(void*));
        
	//fare meglio la gestione degli errori
        if (elf_version(EV_CURRENT) == EV_NONE){
                printf("ELF library initialization failed:\n");
		return;	
	}
	//Opening running executable file, name obtained in  /proc/self/cmdline
        if ((fd = open(file, O_RDONLY, 0)) < 0){
		printf("Can't open file \n");
		return;
	}
	//copying elf_stats
	if((fstat(fd, &elf_stats))) {
        printf("Could not fstat : %s\n", file);
                close(fd);
        return ;
        }
	//memory allocation for elf copy
        if((base_ptr = (char*)malloc(elf_stats.st_size)) == NULL) {
        printf("Malloc per l'elf non riuscita\n");
        return ;
        }
	#ifdef RM_DEBUG
	printf("File elf size: %d byte\n",elf_stats.st_size);
	#endif
        if((read(fd, base_ptr, elf_stats.st_size)) < elf_stats.st_size) {
        printf("could not read elf file : %s\n", file);
                free(base_ptr);
                close(fd);
        return ;
        }
	//a questo punto ho copiato il file elf in memoria a partire dall'indirizzo
	//adesso mi devo salvare tutti gli indirizzi delle sezioni di codice all'interno di un array
	//per poi disassemblarlo
	#ifdef RM_DEBUG
	printf("Lettura dell'elf riuscita\n");
	#endif	
	
        if ((elf = elf_begin(fd, ELF_C_READ, NULL)) == NULL){ 
                printf("elf_begin() failed\n");
		return;
	}
        ek = elf_kind(elf); 
	
	//lo switch sarebbe meglio toglierlo che poi fa casino nel disassemblamento
        switch (ek) {
        case ELF_K_AR:
                k = "ar(1) archive";
                break;
        case ELF_K_ELF:
                k = "elf object";
                break;
        case ELF_K_NONE:
                k = "data";
                break;
        default:
                k = "unrecognized";
        }

	#ifdef RM_DEBUG
	printf("Elf type %s \n",k);
	printf("Itero attraverso le sezioni dell'elf\n");
	#endif	

	//itero attraverso le sezioni dell'elf
	
	while((scn = elf_nextscn(elf, scn)) != NULL) {
        	//gelf_getshdr(scn, &shdr);
		Elf64_Shdr *shdr64;
		shdr64=elf64_getshdr(scn);

       
		
 	// When we find a section header marked SHT_SYMTAB stop and get symbols
	//access to symbol_table
        	if(shdr64->sh_type == SHT_SYMTAB) {
            
        	    // edata points to our symbol table
	//get data from symbol table
        	    edata = elf_getdata(scn, edata);

       		#ifdef RM_DEBUG

		printf("sh_size : %d,sh_entsize %d\n",shdr64->sh_size,shdr64->sh_entsize);
		#endif

		symbol_count = shdr64->sh_size/shdr64->sh_entsize;

		#ifdef RM_DEBUG

		printf("Simboli : %d\n",symbol_count);
		#endif
            // loop through to grab all symbols
        	    for(i = 0; i < symbol_count; i++) {
                        
                // libelf grabs the symbol data using gelf_getsym()
                        gelf_getsym(edata, i, &sym);
	    //   printf("%s\n", elf_strptr(elf, shdr.sh_link, sym.st_name));
 
                    if(ELF64_ST_TYPE(sym.st_info) == STT_FUNC) {
                        
                    if(sym.st_value != 0) {
			printf("sym.stvalue =  %016x \n",sym.st_value);
                        g_array_append_val(jmp_array, sym.st_value);
 
 
			
        	            }

			}
		}
	}
	}

	#ifdef RM_DEBUG
	printf("******************************Valore contenuti nel jmp_array******************************************* \n");
	for( i=0;i< jmp_array->len;i++){
	//SISTEMA QUESTA COSA DEL COUNT CHE FA SCHIFO
		printf("Posizione : %d Address : %p \n",i,g_array_index(jmp_array,void*,i));
	}
	#endif

	//adesso per ogni indirizzo nel jump array vado a disassemblare

	#ifdef RM_DEBUG
	printf("Creazione del funct array dal jmp array\n");
	#endif
	// Array salti: aggiungo anche code_end
    	g_array_append_val(jmp_array, code_end);
    
	/* copy addresses of all the functions in func_array */
	g_array_append_vals(func_array, jmp_array->data, jmp_array->len);
	    
	// Array funzioni: Ordinamento
	g_array_sort(func_array, compareAddress);
	    
	
	    // Array funzioni: Rimozione doppioni
	for(i=1; i<func_array->len; i++) {
		if(g_array_index(func_array, void*, i) == g_array_index(func_array, void*, i-1)) {
		    g_array_remove_index(func_array, i);
		    i--;
		}
	}

	printf("***************************funct_array******************************\n");
	for(i=0; i<func_array->len; i++) {
		printf("Indice: %d, Indirizzo: %p \n",i,g_array_index(func_array, void*, i));
	}

	
	//devo disassemblare le sezioni codice del elf

         elf_end(elf); 
         close(fd);

        

	//ora che ho aperto il file accedo alle sezioni di codice dell'elf64

	unsigned int dver = 0;
        // Holds the result of the decoding.
        _DecodeResult res;
        // Decoded instruction information.
        _DecodedInst decodedInstructions[MAX_INSTRUCTIONS];
        // next is used for instruction's offset synchronization.
        // decodedInstructionsCount holds the count of filled instructions' array by the decoder.
        unsigned int decodedInstructionsCount = 0, next;

        // Default decoding mode is 32 bits, could be set by command line.
        _DecodeType dt = Decode64Bits;

        // Default offset for buffer is 0, could be set in command line.
        _OffsetType offset = 0;
        char* errch = NULL;


	for( i=0;i< (func_array->len-1);i++){
	
	printf("Valore func_array->len: %d",func_array->len-1);	
	//get the address of each executable code section
        void* jmp_address=g_array_index(func_array,void*,i);
	void *func_start = g_array_index(func_array, void*, i);
        void *func_end = g_array_index(func_array, void*, i+1);
	int buflenght=func_end - func_start;
	
	printf("Posizione : %d Address : %p lunghezzaBuffer : %d start: %p end %p \n",i,g_array_index(func_array,void*,i),buflenght,func_start,func_end);
	

        // Disassembler version.
        dver = distorm_version();
        printf("diStorm version: %u.%u.%u\n", (dver >> 16), ((dver) >> 8) & 0xff, dver & 0xff);

	

        
       
	

	
        // Decode the buffer at given offset (virtual address).
        while (1) {
                // If you get an undefined reference linker error for the following line,
                // change the SUPPORT_64BIT_OFFSET in distorm.h.
                res = distorm_decode(offset,
				 (const unsigned char*)jmp_address,
				 buflenght,
				 dt,
				 decodedInstructions,
				 MAX_INSTRUCTIONS,
				 &decodedInstructionsCount);
                if (res == DECRES_INPUTERR) {
                        // Null buffer? Decode type not 16/32/64?
                        fputs("Input error, halting!\n", stderr);
                       
                        return ;
                }

                for (j = 0; j < decodedInstructionsCount; j++)

                        printf("%0*llx (%02d) %-24s %s%s%s\r\n",
				 dt,
				 jmp_address+decodedInstructions[j].offset,
				 decodedInstructions[j].size,
				 (char*)decodedInstructions[j].instructionHex.p,
				 (char*)decodedInstructions[j].mnemonic.p,
				 decodedInstructions[j].operands.length != 0 ? " " : "",
				 (char*)decodedInstructions[j].operands.p);

                if (res == DECRES_SUCCESS) break; // All instructions were decoded.
                else if (decodedInstructionsCount == 0) break;

                // Synchronize:
                next = (unsigned int)(decodedInstructions[decodedInstructionsCount-1].offset - offset);
                next += decodedInstructions[decodedInstructionsCount-1].size;
                // Advance ptr and recalc offset.
                jmp_address += next; 
                buflenght -= next;
                offset += next;
        }
       
}
		
        return ;
}





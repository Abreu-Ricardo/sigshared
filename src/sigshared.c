/*Copyright 2026  Universidade Federal do Mato Grosso do Sul
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
* 
*    http://www.apache.org/licenses/LICENSE-2.0 
* 
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <pthread.h>
#include <fcntl.h>
#include <unistd.h>

#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/mman.h>  
#include <sys/types.h> 
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <assert.h>
#include <stddef.h>
#include <sched.h>

#include "sigshared.h"
#include "include/spright.h"
#include "include/http.h"


//#ifndef unlikely
//#define unlikely(x) __builtin_expect(!!(x), 0)
//#endif
//
//#ifndef likely
//#define likely(x) __builtin_expect(!!(x), 1)
//#endif

//#include "xsk_kern.skel.h"

//#define SIGSHARED_NAME     "SIGSHARED_MEM"
//#define SIGSHARED_MEMPOOL  "SIGSHARED_MEMPOOL"
//#define SIGSHARED_TAM (1U << 16) * sizeof(struct http_transaction)
//#define N_POSICOES (1U << 16)


void *sigshared_ptr;
struct spright_cfg_s *sigshared_cfg;
int fd_sigshared_mem;
int fd_sigshared_mempool;
int fd_cfg_file;

//struct sigshared_mempool *mempool;
//int matriz[11][2] = {0};

char temp[400];
char dir_temp[256];
int map_fd = -1;


struct sigshared_ringbuffer *ringbuff;
void *sigshared_mempool;
uint64_t rb[N_ELEMENTOS];

int fd_shm = -1;
//pid_t pid_alvo = -1;


int mapa_sinal_fd = -1;
//char *path_fixo = "/mydata/spright/dados/mapa_sinal";
char *path_fixo = "/mydata/sigshared/dados/mapa_sinal";

/********************************************************************************************/
 void *sigshared_create_mem(){

    fd_sigshared_mem = shm_open(SIGSHARED_NAME, O_CREAT | O_RDWR, 0777);
    if (fd_sigshared_mem < 0){ 
        perror("ERRO NO shm_open()");
        exit(1);
    }

    int ret_ftruncate = ftruncate(fd_sigshared_mem, SIGSHARED_TAM); 
    if ( ret_ftruncate == -1 ){
        perror("ERRO NO ftruncate()");
        exit(1);  
    }

    printf("Terminando sigshared_create_mem()...\n");
    //sigshared_ptr   = ( void *) mmap(0, tam_sigshared, PROT_WRITE, MAP_SHARED, fd_sigshared_mem, 0);
    return ( void *) mmap(0, SIGSHARED_TAM, PROT_WRITE, MAP_SHARED, fd_sigshared_mem, 0);
}

/********************************************************************************************/
// retorna ponteiro pro inicio da mem compart.
 void *sigshared_ptr_mem(){

    //*fd_sigshared_mem = shm_open(SIGSHARED_NAME, O_CREAT | O_RDWR, 0777);
    fd_sigshared_mem = shm_open(SIGSHARED_NAME, O_CREAT | O_RDWR, 0777);
    if ( fd_sigshared_mem < 0){ 
        perror("ERRO NO shm_open()");
        exit(1);
    }

    printf("Terminando sigshared_ptr_mem()...\n");
    return ( void *) mmap(0, SIGSHARED_TAM, PROT_WRITE, MAP_SHARED, fd_sigshared_mem, 0);
}

/********************************************************************************************/
// Cria a memoria do cfg e retorna o ponteiro para a struct spright_cfg_s *
 struct spright_cfg_s *sigshared_cfg_mem(){

    fd_cfg_file = shm_open("CFG_MEM", O_CREAT | O_RDWR, 0777);
    if (fd_cfg_file < 0){ 
        perror("ERRO NO shm_open()");
        exit(1);
    }

    int ret_ftruncate = ftruncate(fd_cfg_file, sizeof(struct spright_cfg_s)); 
    if ( ret_ftruncate == -1 ){
        perror("ERRO NO ftruncate()");
        exit(1);  
    }

    printf("Terminando sigshared_cfg_mem()...\n");
    //sigshared_ptr   = ( void *) mmap(0, tam_sigshared, PROT_WRITE, MAP_SHARED, fd_sigshared_mem, 0);
    return ( struct spright_cfg_s *) mmap(0, sizeof(struct spright_cfg_s), PROT_WRITE, MAP_SHARED, fd_cfg_file, 0);
}

/********************************************************************************************/
// retorna o ponteiro para a memoria da regiao de configuracao
 struct spright_cfg_s *sigshared_cfg_ptr(){

    fd_cfg_file = shm_open("CFG_MEM", O_CREAT | O_RDWR, 0777);
    if (fd_cfg_file < 0){ 
        perror("ERRO NO shm_open()");
        exit(1);
    }


    printf("Terminando sigshared_cfg_ptr()...\n");
    //sigshared_ptr   = ( void *) mmap(0, tam_sigshared, PROT_WRITE, MAP_SHARED, fd_sigshared_mem, 0);
    return ( struct spright_cfg_s *) mmap(0, sizeof(struct spright_cfg_s), PROT_WRITE, MAP_SHARED, fd_cfg_file, 0);
}

/********************************************************************************************/
// Atualiza o mapa eBPF com nome do mapa e valor a serem utilizados para salvar
 int sigshared_update_map(char *map_name, int fn_id, int pid, int *map_fd){

    char temp[256];
    char *dir_temp = getenv("SIGSHARED");
    //int map_fd;

    //mapa_sinal_fd = bpf_obj_get(path_fixo);
    sprintf(temp, "%s/dados/%s", dir_temp, map_name);
    *map_fd = bpf_obj_get(temp);

    if(bpf_map_update_elem(*map_fd, &fn_id, &pid, BPF_ANY) < 0){
    //if(bpf_map_update_elem(mapa_sinal_fd, &fn_id, &pid, BPF_ANY) < 0){
        perror("Erro ao atualizar o mapa eBPF");
        return -1;
    }

    printf("==update_map(%d)== Mapa atualizado...\n", getpid());
    return 0;
}



/********************************************************************************************/
// Retorna o pid, passe o nome do mapa e a chave
pid_t sigshared_lookup_map(char *map_name, int key, int *mapa_sig_fd){

	//printf("==lookup_map==\n");

	char temp[256];
	char *dir_temp = getenv("SIGSHARED");
	//int map_fd;
	pid_t pid_ret;

	if(mapa_sig_fd <= 0){
		sprintf(temp, "%s/dados/%s", dir_temp, map_name);
		//map_fd = bpf_obj_get(temp);
		*mapa_sig_fd = bpf_obj_get(temp);
	}

	//if( bpf_map_lookup_elem(map_fd, &key, &pid_ret) < 0 ){
	if( bpf_map_lookup_elem(*mapa_sig_fd, &key, &pid_ret) < 0 ){
		//printf("Erro ao consultar o mapa eBPF | map_fd:%d  key:%d  pid_ret:%d\n", map_fd, key , pid_ret);
		printf("Erro ao consultar o mapa eBPF | map_sinal_fd:%d  key:%d  pid_ret:%d\n", *mapa_sig_fd, key, pid_ret);
		return -1;
	}

	//printf("==lookup_map== Voltando com o PID: %d\n", pid_ret);
	//close(map_fd);

	return pid_ret;
}


/********************************************************************************************/
/********************************************************************************************/
struct sigshared_ringbuffer *sigshared_mempool_create(){

    int fd_ringbuff = shm_open(RINGBUF_REGION, O_RDWR | O_CREAT, 0777);
    if (fd_ringbuff < 0){
        perror("Erro ao criar mem compart de ringbuff");
        return NULL;
    }

    int ret_truncate = ftruncate( fd_ringbuff, RINGBUF_TAM);
    if(ret_truncate < 0){
        perror("Erro ao atribuir tamanho do ringbuff");
        return NULL;
    }

    ringbuff = (struct sigshared_ringbuffer *) mmap(0, RINGBUF_TAM, PROT_WRITE, MAP_SHARED, fd_ringbuff, 0);
    for(uint64_t i=0; i < N_ELEMENTOS; i++){
        ringbuff->ringbuffer[i] = i;
        ringbuff->rb[i] = i;
	rb[i] = i;
    }

    // Ultima posicao pois, na criacao todas 
    // posicoes estao livres
    ringbuff->head = 0;
    ringbuff->tail = N_ELEMENTOS - 1;


    return (struct sigshared_ringbuffer *) mmap(0, RINGBUF_TAM, PROT_WRITE, MAP_SHARED, fd_ringbuff, 0);
}

/********************************************************************************************/

 struct sigshared_ringbuffer *sigshared_mempool_ptr(){
    int fd_ringbuff = shm_open(RINGBUF_REGION, O_CREAT | O_RDWR, 0777);
    if (fd_ringbuff < 0){ 
        perror("ERRO NO shm_open()");
        exit(1);
    }

    return ( struct sigshared_ringbuffer *) mmap(0, RINGBUF_TAM, PROT_WRITE, MAP_SHARED, fd_ringbuff, 0);
}

/********************************************************************************************/
//uint64_t sigshared_mempool_get(void *ptr){
uint64_t sigshared_mempool_get(){

    uint64_t temp;
    //usleep(100);
    //usleep(300);
    // Se a cabeca + 1 for igual a posicao final
    if (ringbuff->head+1 == N_ELEMENTOS ){

        ringbuff->head = 0;
        //printf("<mempool_get()> head+1 == N_ELEMENTOS | head:%ld tail:%ld\n", ringbuff->head, ringbuff->tail);

        if (ringbuff->head != ringbuff->tail){
            //printf("<mempool_get()> head != tail\n");
            temp = ringbuff->rb[ ringbuff->ringbuffer[ringbuff->head] ];
            ringbuff->head++;
	    //printf("==sigsahred_mempool_get== addr retornado:%ld\n", temp);
            return temp;
        
	}
        else{
	    //printf("+++caiu no ELSE+++\n");
            while(ringbuff->head == ringbuff->tail){
                printf("+++ERRO1+++ <sigshared_mempool_get()> HEAD == TAIL | head:%ld tail:%ld\n", ringbuff->head, ringbuff->tail);
                //usleep(100);
            }

            //temp =  ringbuff->ringbuffer[ringbuff->head];
            temp =  ringbuff->rb[ringbuff->ringbuffer[ringbuff->head]];
	    //printf("==sigsahred_mempool_get== addr retornado:%ld\n", temp);
            return temp;
        }
    }

    else if (ringbuff->head+1 != ringbuff->tail){
	//printf("head+1 != tail\n");
        temp = ringbuff->rb[ringbuff->ringbuffer[ringbuff->head]];
        ringbuff->head++;
	//printf("==sigsahred_mempool_get== addr retornado:%ld\n", temp);
        return temp;
    }

    else{
        //printf("++++ERRO2+++ <sigshared_mempool_get()> HEAD == TAIL \n");
        while(ringbuff->head == ringbuff->tail){
                printf("<sigshared_mempool_get()> HEAD == TAIL \n");
                //usleep(100);
        }

        temp =  ringbuff->rb[ringbuff->ringbuffer[ringbuff->head]];
        ringbuff->head++;
	//printf("==sigsahred_mempool_get== addr retornado:%ld\n", temp);
        return temp;
    }
    //printf("Nao caiu em nenhum if\n");
    return -1; // Trocar isso,  se devolve um uint64_t o valor negativo do -1 n vai indicar o erro
}

/********************************************************************************************/
//int sigshared_mempool_put(struct http_transaction *txn, uint64_t addr){
int sigshared_mempool_put( uint64_t addr){

    //struct http_transaction *txn = (struct http_transaction *) &sigshared_ptr[addr];

    //memset(txn, 0, sizeof(struct http_transaction));
    // Put chama mas ja esta na ultima posicao
    if(ringbuff->tail+1 == N_ELEMENTOS){
        ringbuff->tail = 0;

        if ( ringbuff->tail != ringbuff->head ){
            ringbuff->ringbuffer[ringbuff->tail] = addr;
            ringbuff->tail++;
            return 0;
        }
        else{
            printf("ERRO1==sigshared_mempool_put== HEAD == TAIL \n");
            ringbuff->ringbuffer[ringbuff->tail] = addr;
            ringbuff->head = ringbuff->tail+1; 
            return 0;
        }
    }
    else if( ringbuff->tail+1 != ringbuff->head ){
        ringbuff->ringbuffer[ringbuff->tail] = addr;
        ringbuff->tail++;
        return 0;
    }

    // Se tail alcanca head, buffer esta vazio
    // entao por head na frente de tail para consumir
    // as posicoes da frente
    else if (ringbuff->tail+1 == ringbuff->head){
        //ringbuff->tail = N_ELEMENTOS - 1; 
        ringbuff->head = ringbuff->tail; 
        ringbuff->tail++;
        //if(ringbuff->head == N_ELEMENTOS-1)
        //    ringbuff->head= 0;
        //printf("ERRO2==sigshared_mempool_put== HEAD == TAIL \n");
        //sigshared_mempool_put(addr);
        //return -1;
        return 0;
    }

    return 0;
}

/********************************************************************************************/
//struct http_transaction *sigshared_mempool_access(struct http_transaction *temp, uint64_t addr){
struct http_transaction *sigshared_mempool_access(void **temp, uint64_t addr){

	//printf("==sigshared_mempool_access== addr:%ld\n", addr);
	//temp = NULL;
	*temp = (void *)sigshared_ptr;
	//printf("DPS DE  *temp\n");
	
	//*temp = (struct http_transaction *) sigshared_ptr; //(struct http_transaction *) mmap(0, SIGSHARED_TAM, PROT_WRITE, MAP_SHARED, fd_sigshared_mem, 0);
	//printf("PEGOU ptr na mem...\n");

	//printf("nf_id:%d | texto:%s\n",temp[addr].nf_id, temp[addr].vetor_teste);
	if (unlikely(*temp == NULL)){
	//if (unlikely(aux == NULL)){
		printf("sigshared_mempool_access: mempool == NULL\n");
		return NULL;
	}

	
	//else if(&temp[addr] >= &temp[0] && &temp[addr] <= &temp[N_ELEMENTOS-1]){
	else if(likely(addr >= 0 && addr <= N_ELEMENTOS-1)){
		//printf("mempool_access() | addr:%ld\n", addr);
		
		*temp += sizeof(struct http_transaction) * addr;
		//aux->addr = addr;
		//*temp[addr].addr = addr;
		//*temp = (void *) addr;
		//printf("Antes de retornar, passou temp[addr]\n");		
		//return &temp[addr];
		return *temp;
	}
	else{
		printf("==sigshared_mempool_access== ADDR invalido\n");
		return NULL;
	}
}
/*********************************************************************/



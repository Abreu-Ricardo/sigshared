/*
# Copyright 2022 University of California, Riverside
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0
*/

#include <errno.h>
#include <math.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <time.h>
#include <unistd.h>

#include "../include/http.h"
#include "../include/io.h"
#include "../include/spright.h"

#include "../sigshared.h"

int mapa_fd;
int matriz[11][2] = {0};
sigset_t set;



static int pipefd_rx[UINT8_MAX][2];
static int pipefd_tx[UINT8_MAX][2];

#define MAX_ADS_TO_SERVE 1

char *ad_name[] = {"clothing", "accessories", "footwear", "hair", "decor", "kitchen"};

static Ad getAdsByCategory(char contextKey[])
{
    if (strcmp(contextKey, "clothing") == 0)
    {
        Ad ad = {"/product/66VCHSJNUP", "Tank top for sale. 20 off."};
        return ad;
    }
    else if (strcmp(contextKey, "accessories") == 0)
    {
        Ad ad = {"/product/1YMWWN1N4O", "Watch for sale. Buy one, get second kit for free"};
        return ad;
    }
    else if (strcmp(contextKey, "footwear") == 0)
    {
        Ad ad = {"/product/L9ECAV7KIM", "Loafers for sale. Buy one, get second one for free"};
        return ad;
    }
    else if (strcmp(contextKey, "hair") == 0)
    {
        Ad ad = {"/product/2ZYFJ3GM2N", "Hairdryer for sale. 50 off."};
        return ad;
    }
    else if (strcmp(contextKey, "decor") == 0)
    {
        Ad ad = {"/product/0PUK6V6EV0", "Candle holder for sale. 30 off."};
        return ad;
    }
    else if (strcmp(contextKey, "kitchen") == 0)
    {
        Ad ad = {"/product/6E92ZMYYFZ", "Mug for sale. Buy two, get third one for free"};
        return ad;
    }
    else
    {
        log_debug("No Ad found.");
        Ad ad = {"", ""};
        return ad;
    }
}

static Ad getRandomAds()
{
    int i;
    int ad_index;

    for (i = 0; i < MAX_ADS_TO_SERVE; i++)
    {
        ad_index = rand() % 6;
        if (strcmp(ad_name[ad_index], "clothing") == 0)
        {
            Ad ad = {"/product/66VCHSJNUP", "Tank top for sale. 20 off."};
            return ad;
        }
        else if (strcmp(ad_name[ad_index], "accessories") == 0)
        {
            Ad ad = {"/product/1YMWWN1N4O", "Watch for sale. Buy one, get second kit for free"};
            return ad;
        }
        else if (strcmp(ad_name[ad_index], "footwear") == 0)
        {
            Ad ad = {"/product/L9ECAV7KIM", "Loafers for sale. Buy one, get second one for free"};
            return ad;
        }
        else if (strcmp(ad_name[ad_index], "hair") == 0)
        {
            Ad ad = {"/product/2ZYFJ3GM2N", "Hairdryer for sale. 50 off."};
            return ad;
        }
        else if (strcmp(ad_name[ad_index], "decor") == 0)
        {
            Ad ad = {"/product/0PUK6V6EV0", "Candle holder for sale. 30 off."};
            return ad;
        }
        else if (strcmp(ad_name[ad_index], "kitchen") == 0)
        {
            Ad ad = {"/product/6E92ZMYYFZ", "Mug for sale. Buy two, get third one for free"};
            return ad;
        }
        else
        {
            log_debug("No Ad found.");
            Ad ad = {"", ""};
            return ad;
        }
    }

    log_debug("No Ad found.");
    Ad ad = {"", ""};
    return ad;
}

static AdRequest *GetContextKeys(struct http_transaction *in)
{
    return &(in->ad_request);
}

static void PrintContextKeys(AdRequest *ad_request)
{
    int i;
    for (i = 0; i < ad_request->num_context_keys; i++)
    {
        log_debug("context_word[%d]=%s\t\t\n", i + 1, ad_request->ContextKeys[i]);
    }
    // printf("\n");
}

static void PrintAdResponse(struct http_transaction *in)
{
    int i;
    log_debug("Ads in AdResponse:");
    for (i = 0; i < in->ad_response.num_ads; i++)
    {
        log_debug("Ad[%d] RedirectUrl: %s\tText: %s", i + 1, in->ad_response.Ads[i].RedirectUrl,
                 in->ad_response.Ads[i].Text);
    }
    // printf("\n");
}

static void GetAds(struct http_transaction *in)
{
    log_debug("[GetAds] received ad request");

    AdRequest *ad_request = GetContextKeys(in);
    PrintContextKeys(ad_request);
    in->ad_response.num_ads = 0;

    if (ad_request->num_context_keys > 0)
    {
        log_debug("Constructing Ads using received context.");
        int i;
        for (i = 0; i < ad_request->num_context_keys; i++)
        {
            log_debug("context_word[%d]=%s", i + 1, ad_request->ContextKeys[i]);
            Ad ad = getAdsByCategory(ad_request->ContextKeys[i]);

            strcpy(in->ad_response.Ads[i].RedirectUrl, ad.RedirectUrl);
            strcpy(in->ad_response.Ads[i].Text, ad.Text);
            in->ad_response.num_ads++;
        }
    }
    else
    {
        log_debug("No Context provided. Constructing random Ads.");
        Ad ad = getRandomAds();

        strcpy(in->ad_response.Ads[0].RedirectUrl, ad.RedirectUrl);
        strcpy(in->ad_response.Ads[0].Text, ad.Text);
        in->ad_response.num_ads++;
    }

    if (in->ad_response.num_ads == 0)
    {
        log_debug("No Ads found based on context. Constructing random Ads.");
        Ad ad = getRandomAds();

        strcpy(in->ad_response.Ads[0].RedirectUrl, ad.RedirectUrl);
        strcpy(in->ad_response.Ads[0].Text, ad.Text);
        in->ad_response.num_ads++;
    }

    log_debug("[GetAds] completed request");
}

static void MockAdRequest(struct http_transaction *in)
{
    int num_context_keys = 2;
    int i;

    in->ad_request.num_context_keys = 0;
    for (i = 0; i < num_context_keys; i++)
    {
        in->ad_request.num_context_keys++;
        strcpy(in->ad_request.ContextKeys[i], ad_name[i]);
    }
}

static void *nf_worker(void *arg)
{
    struct http_transaction *txn = NULL;
    ssize_t bytes_written;
    ssize_t bytes_read;
    uint8_t index;

    /* TODO: Careful with this pointer as it may point to a stack */
    index = (uint64_t)arg;

    while (1)
    {
        bytes_read = read(pipefd_rx[index][0], &txn, sizeof(struct http_transaction *));
        if (unlikely(bytes_read == -1))
        {
            log_error("read() error: %s", strerror(errno));
            return NULL;
        }

        if (strcmp(txn->rpc_handler, "GetAds") == 0)
        {
            GetAds(txn);
        }
        else
        {
            log_warn("%s() is not supported", txn->rpc_handler);
            log_debug("\t\t#### Run Mock Test ####");
            MockAdRequest(txn);
            GetAds(txn);
            PrintAdResponse(txn);
        }

	//printf("==ad(%d)== ANTES: next_fn:%d caller_fn:%d\n", getpid(), txn->next_fn, txn->caller_fn);
        
	// Devolve para quem o chamou 
        txn->next_fn = txn->caller_fn;
        txn->caller_fn = AD_SVC;

	//if (txn->caller_fn != AD_SVC){
	//	//printf("### next_fn:%d == caller_fn:%d ###\n", txn->next_fn, txn->caller_fn);
	//	//txn->next_fn = txn->caller_fn;
	//	txn->next_fn = FRONTEND;
	//}
	//txn->caller_fn = AD_SVC;

	//printf("==ad(%d)== DEPOIS: next_fn:%d caller_fn:%d\n\n", getpid(), txn->next_fn, txn->caller_fn);

        bytes_written = write(pipefd_tx[index][1], &txn, sizeof(struct http_transaction *));
        if (unlikely(bytes_written == -1)){
            log_error("write() error: %s", strerror(errno));
            return NULL;
        }
    }

    return NULL;
}

static void *nf_rx(void *arg)
{
    struct http_transaction *txn = NULL;
    ssize_t bytes_written;
    uint8_t i;
    //int ret;
    //uint64_t addr;

    for (i = 0;; i = (i + 1) % sigshared_cfg->nf[fn_id - 1].n_threads){
        //ret = io_rx((void **)&txn);
        //addr = io_rx(txn, sigshared_ptr, &set);
        //txn = io_rx(txn, sigshared_ptr, &set);
        io_rx((void **)&txn, sigshared_ptr, &set);
        //if (unlikely(addr == -1)){
        //    log_error("io_rx() error");
        //    return NULL;
        //}

	//txn = sigshared_mempool_access(txn, addr);
	if(unlikely(txn == NULL)){
		printf("==adservice== ERRO mempool_access retornou NULL\n");
		return NULL;
	}

        bytes_written = write(pipefd_rx[i][1], &txn, sizeof(struct http_transaction *));
        if (unlikely(bytes_written == -1)){
            log_error("write() error: %s", strerror(errno));
            return NULL;
        }
    }

    return NULL;
}

// signalfd implementation
//static void *nf_rx(void *arg){
//    //struct http_transaction *txn = NULL;
//    struct http_transaction *txn;
//    ssize_t bytes_written;
//    uint8_t i;
//    //int ret;
//    //uint64_t addr;
//    //int pid = getpid();
//
//    sigset_t block_set;
//
//    sigemptyset(&block_set);       
//    sigaddset(&block_set, SIGRTMIN+1); 
//    pthread_sigmask(SIG_BLOCK, &block_set, NULL);
//
//    //txn = (struct http_transaction *) mmap(0, SIGSHARED_TAM, PROT_WRITE, MAP_SHARED, fd_sigshared_mem, 0);
//
//    struct epoll_event eventos[UINT8_MAX];
//    int n;
//    int sigfd = signalfd(-1, &block_set, SFD_NONBLOCK | SFD_CLOEXEC);
//
//    int epfd = epoll_create1(0);
//    if (unlikely(epfd == -1))
//    {
//        log_error("epoll_create1() error: %s", strerror(errno));
//        return NULL;
//    }
//
//    eventos[0].events = EPOLLIN; // The associated file is available for read(2) operations.
//    eventos[0].data.fd = sigfd;
//
//    if (epoll_ctl(epfd, EPOLL_CTL_ADD, sigfd, &eventos[0]) < 0) {
//        perror("epoll_ctl");
//        exit(1);
//    }
//
//    for (i = 0;; i = (i + 1) % sigshared_cfg->nf[fn_id - 1].n_threads){
//
//	//log_info("Recebendo sinal...");
//        //ret = io_rx((void **)&txn);
//        //addr = io_rx(txn, sigshared_ptr, &set);
//        //txn = io_rx(txn, sigshared_ptr, &set);
//        
//	//io_rx((void **)&txn, sigshared_ptr, &set);
//        
//	//if (unlikely(ret == -1))
//        //if (unlikely(addr == -1)){
//        //    log_error("io_rx() error");
//        //    return NULL;
//        //}
//	
//	//printf("Esperando sinal com epoll_wait()...\n");
//	n = epoll_wait(epfd, eventos, UINT8_MAX, -1);  // -1 = block indefinitely
//        
//        if (n < 0) {
//            if (errno == EINTR)
//                continue;
//            perror("epoll_wait");
//            break;
//        }
//
//        for (int j = 0; j < n; j++) {
//            if (eventos[j].data.fd == sigfd) {
//                
//		struct signalfd_siginfo si;
//                ssize_t res = read(sigfd, &si, sizeof(si));
//                if (res != sizeof(si)) {
//                    perror("read(signalfd)");
//                    continue;
//                }
//
//                //printf("Received signal %d from PID %d | data: %ld\n", si.ssi_signo, si.ssi_pid, (uint64_t)si.ssi_ptr);
//		txn = sigshared_mempool_access( (void**)&txn, (uint64_t)si.ssi_ptr );
//		if(unlikely(txn == NULL)){
//			printf("==frontend== txn retornou NULL\n");
//			exit(1);
//		}
//		
//		bytes_written = write(pipefd_rx[i][1], &txn, sizeof(struct http_transaction *));
//		if (unlikely(bytes_written == -1)){
//			log_error("write() error: %s", strerror(errno));
//			return NULL;
//		}
//	    }
//	}
//
//
//
//	//printf("==frontend== dps sigshared_mempool_access() | txn->addr:%ld\n", txn->addr);
//        //log_info("(ADDR RX:%ld), HOP: %u, Next Fn: %u, Caller Fn: %s (#%u) ", txn->addr, txn->hop_count, txn->next_fn, txn->caller_nf, txn->caller_fn);
//    }
//
//    return NULL;
//}




static void *nf_tx(void *arg)
{
    struct epoll_event event[UINT8_MAX]; /* TODO: Use Macro */
    struct http_transaction *txn = NULL;
    ssize_t bytes_read;
    uint8_t i;
    int n_fds;
    int epfd;
    int ret;
    int ret_io;
    int pid = getpid();

    epfd = epoll_create1(0);
    if (unlikely(epfd == -1))
    {
        log_error("epoll_create1() error: %s", strerror(errno));
        return NULL;
    }

    for (i = 0; i < sigshared_cfg->nf[fn_id - 1].n_threads; i++)
    {
        ret = set_nonblocking(pipefd_tx[i][0]);
        if (unlikely(ret == -1))
        {
            return NULL;
        }

        event[0].events = EPOLLIN;
        event[0].data.fd = pipefd_tx[i][0];

        ret = epoll_ctl(epfd, EPOLL_CTL_ADD, pipefd_tx[i][0], &event[0]);
        if (unlikely(ret == -1))
        {
            log_error("epoll_ctl() error: %s", strerror(errno));
            return NULL;
        }
    }

    while (1)
    {
        n_fds = epoll_wait(epfd, event, sigshared_cfg->nf[fn_id - 1].n_threads, -1);
        if (unlikely(n_fds == -1))
        {
            log_error("epoll_wait() error: %s", strerror(errno));
            return NULL;
        }

        for (i = 0; i < n_fds; i++)
        {
            bytes_read = read(event[i].data.fd, &txn, sizeof(struct http_transaction *));
            if (unlikely(bytes_read == -1))
            {
                log_error("read() error: %s", strerror(errno));
                return NULL;
            }

            //log_debug("Route id: %u, Hop Count %u, Next Hop: %u, Next Fn: %u, Caller Fn: %s (#%u), RPC Handler: %s()", txn->route_id, txn->hop_count, sigshared_cfg->route[txn->route_id].hop[txn->hop_count], txn->next_fn, txn->caller_nf, txn->caller_fn, txn->rpc_handler);
            //log_info("Route id: %u, Hop Count %u, Next Hop: %u, Next Fn: %u, Caller Fn: %s (#%u), RPC Handler: %s()", txn->route_id, txn->hop_count, sigshared_cfg->route[txn->route_id].hop[txn->hop_count], txn->next_fn, txn->caller_nf, txn->caller_fn, txn->rpc_handler);

            //ret = io_tx(txn->addr, txn->next_fn, &mapa_fd);
            //ret_io = io_tx_matriz(txn->addr, txn->next_fn, &mapa_fd, matriz);
	    ret_io = io_tx_matriz(txn->addr, txn->next_fn, &mapa_fd, pid, matriz, matriz[txn->next_fn][1]);
            //if (unlikely(ret == -1))
            if (unlikely(ret_io == -1))
            {
                log_error("io_tx() error");
                return NULL;
            }
        }
    }

    return NULL;
}

/* TODO: Cleanup on errors */
static int nf(uint8_t nf_id)
{
    //const struct rte_memzone *memzone = NULL;
    pthread_t thread_worker[UINT8_MAX];
    pthread_t thread_rx;
    pthread_t thread_tx;
    uint8_t i;
    int ret;

    fn_id = nf_id;

    int pid = getpid();

    matriz[nf_id][1] = pid;
    if( sigshared_update_map("mapa_sinal", fn_id, pid, &mapa_fd) < 0  ){
        printf("Erro ao atualizar mapa\n");
        return 0;
    }

    for (i = 0; i < sigshared_cfg->nf[fn_id - 1].n_threads; i++)
    {
        ret = pipe(pipefd_rx[i]);
        if (unlikely(ret == -1))
        {
            log_error("pipe() error: %s", strerror(errno));
            return -1;
        }

        ret = pipe(pipefd_tx[i]);
        if (unlikely(ret == -1))
        {
            log_error("pipe() error: %s", strerror(errno));
            return -1;
        }
    }

    // IO_RX
    ret = pthread_create(&thread_rx, NULL, &nf_rx, NULL);
    if (unlikely(ret != 0))
    {
        log_error("pthread_create() error: %s", strerror(ret));
        return -1;
    }

    // IO_TX
    ret = pthread_create(&thread_tx, NULL, &nf_tx, NULL);
    if (unlikely(ret != 0))
    {
        log_error("pthread_create() error: %s", strerror(ret));
        return -1;
    }

    // Cria workers
    for (i = 0; i < sigshared_cfg->nf[fn_id - 1].n_threads; i++)
    {
        ret = pthread_create(&thread_worker[i], NULL, &nf_worker, (void *)(uint64_t)i);
        if (unlikely(ret != 0))
        {
            log_error("pthread_create() error: %s", strerror(ret));
            return -1;
        }
	//printf("Threads criadas: %d de %d\n", i, sigshared_cfg->nf[fn_id - 1].n_threads);
    }

    for (i = 0; i < sigshared_cfg->nf[fn_id - 1].n_threads; i++)
    {
        ret = pthread_join(thread_worker[i], NULL);
        if (unlikely(ret != 0))
        {
            log_error("pthread_join() error: %s", strerror(ret));
            return -1;
        }
    }

    ret = pthread_join(thread_rx, NULL);
    if (unlikely(ret != 0))
    {
        log_error("pthread_join() error: %s", strerror(ret));
        return -1;
    }

    ret = pthread_join(thread_tx, NULL);
    if (unlikely(ret != 0))
    {
        log_error("pthread_join() error: %s", strerror(ret));
        return -1;
    }

    for (i = 0; i < sigshared_cfg->nf[fn_id - 1].n_threads; i++)
    {
        ret = close(pipefd_rx[i][0]);
        if (unlikely(ret == -1))
        {
            log_error("close() error: %s", strerror(errno));
            return -1;
        }

        ret = close(pipefd_rx[i][1]);
        if (unlikely(ret == -1))
        {
            log_error("close() error: %s", strerror(errno));
            return -1;
        }

        ret = close(pipefd_tx[i][0]);
        if (unlikely(ret == -1))
        {
            log_error("close() error: %s", strerror(errno));
            return -1;
        }

        ret = close(pipefd_tx[i][1]);
        if (unlikely(ret == -1))
        {
            log_error("close() error: %s", strerror(errno));
            return -1;
        }
    }

    return 0;
}



int main(int argc, char **argv){
    log_set_level_from_env();

    log_set_level(LOG_INFO);

    uint8_t nf_id;
    int ret;


    char settar_cpuf[30];

    printf("Atribuindo processo para a CPU 12...\n");
    sprintf(settar_cpuf, "taskset -cp 12 %d", getpid());
    int ret_sys = system(settar_cpuf);
    if( ret_sys == -1 || ret_sys == 127 ){
	    log_error("Erro ao settar CPU");
	    exit(1);
    }


    sigshared_ptr = sigshared_ptr_mem();
    if(sigshared_ptr == NULL){
        log_error("ERRO NO sigshared_ptr");
        return 1;
    }

    sigshared_cfg = sigshared_cfg_ptr();
    if(sigshared_cfg == NULL){
        log_error("ERRO NO sigshared_cfg");
        return 1;
    }

    //log_info("Config name: %s", sigshared_cfg->name);

    sigemptyset(&set);
    sigaddset(&set, SIGRTMIN+1);
    sigprocmask(SIG_BLOCK, &set, NULL);


    errno = 0;
    nf_id = strtol(argv[argc-1], NULL, 10);
    if (unlikely(errno != 0 || nf_id < 1))
    {
        log_error("Invalid value for Network Function ID");
        goto error_1;
    }

    ret = nf(nf_id);
    if (unlikely(ret == -1))
    {
        log_error("nf() error");
        goto error_1;
    }


    return 0;

error_1:
    printf("Erro ao inicializar nf\n");
    //rte_eal_cleanup();
//error_0:
//    return 1;
}

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
#include "../include/shm_rpc.h"
#include "../include/spright.h"
#include "../include/utility.h"

#include <execinfo.h>
#include <sys/signalfd.h>
#include "../sigshared.h"

int mapa_fd;
int matriz[11][2] = {0};
sigset_t set;

int pid; 



static int pipefd_rx[UINT8_MAX][2];
static int pipefd_tx[UINT8_MAX][2];

// char defaultCurrency[5] = "CAD";

__always_inline char *find_char(const char *s, char c) {
    if (!s) return NULL;
    while (*s && *s != c)
        s++;
    return *s ? (char*)s : NULL;
}

static void setCurrencyHandler(struct http_transaction *txn){

    log_debug("Call setCurrencyHandler");
    //char *query = httpQueryParser(txn->request);
    
    
    //char *aux = NULL;
    //char *query = httpQueryParser(txn->request, aux, HTTP_MSG_LENGTH_MAX);
    char *query = httpQueryParser(txn->request);
    if (!query) {
    //if (!aux) {
            log_error("httpQueryParser retornou NULL");
            exit(1);
            //return;
    }

    //char *req = txn->request;
    ////char tmp[600]; 
    //char tmp[HTTP_MSG_LENGTH_MAX + 1]; 
    ////strcpy(tmp, req);
    //strncpy(tmp, req, sizeof(tmp) -1);
    //tmp[sizeof(tmp) -1] = '\0';
    //
    //char *saveptr = NULL;
    ////char *start_of_path = strtok(tmp, " ");
    //char *start_of_path = strtok_r(tmp, " ", &saveptr);
    //if( unlikely(start_of_path == NULL) ){
    //    log_error("start_of_path == NULL, erro no strtok");
    //	exit(1);
    //}

    ////start_of_path = strtok(NULL, " ");
    //start_of_path = strtok_r(NULL, " ", &saveptr);
    //if( unlikely(start_of_path == NULL)){
    //    log_error("start_of_path == NULL, erro no strtok");
    //	exit(1);
    //}
    ////printf("%s\n", start_of_path); 

    ////char *query = strchr(start_of_path, '?') + 1;
    //char *query = find_char(start_of_path, '?') ;
    //if( unlikely(!query || query == NULL)){
    //	log_error("query == NULL, erro em strchr");
    //    //returnResponse(txn);
    //    return;
    //    //exit(1);
    //}
    //query +=1;
    // printf("%s\n", start_of_path); //printing the token
    
    //char *start_of_query = strchr(start_of_path, '?') + 1;

    //log_info("QUERY: %s", query);
    char _defaultCurrency[5] = "CAD";
    strcpy(_defaultCurrency, strchr(query, '=') + 1);
    


    txn->hop_count += 100;
    txn->next_fn = GATEWAY; // Hack: force gateway to return a response
    
    //free(query);

}

static void homeHandler(struct http_transaction *txn){

    log_debug("Call homeHandler ### Hop: %u", txn->hop_count);
    //log_info("Call homeHandler ### Hop: %u", txn->hop_count);

    if (txn->hop_count == 0){
        // next_fn = currency.c
        getCurrencies(txn);
    }
    else if (txn->hop_count == 1){
        // next_fn = productcatalog.c
        getProducts(txn);
        txn->productViewCntr = 0;
    }
    else if (txn->hop_count == 2){
        // next_fn = cart.c
        getCart(txn);
    }
    else if (txn->hop_count == 3){
        // next_fn = currency.c
        convertCurrencyOfProducts(txn);
        homeHandler(txn);
    }
    else if (txn->hop_count == 4){
        // next_fn = ad.c
        chooseAd(txn);
    }
    else if (txn->hop_count == 5){
        // next_fn = gateway.c
        returnResponse(txn);
    }
    else{
        // next_fn = gateway.c
        log_warn("homeHandler doesn't know what to do for HOP %u.", txn->hop_count);
        returnResponse(txn);
    }
    return;
}

static void productHandler(struct http_transaction *txn)
{
    log_debug("Call productHandler ### Hop: %u", txn->hop_count);
    //log_info("Call productHandler ### Hop: %u", txn->hop_count);

    if (txn->hop_count == 0)
    {
        // next_fn = productcatalog.c
        getProduct(txn);
        txn->productViewCntr = 0;
    }
    else if (txn->hop_count == 1)
    {
        // next_fn = currency.c
        getCurrencies(txn);
    }
    else if (txn->hop_count == 2)
    {
        // next_fn = cart.c
        getCart(txn);
    }
    else if (txn->hop_count == 3)
    {
        // next_fn = recommendations.c
        // next_fn = currency.c
        convertCurrencyOfProduct(txn);
    }
    else if (txn->hop_count == 4)
    {
        // next_fn = ad.c
        chooseAd(txn);
    }
    else if (txn->hop_count == 5)
    {
        // next_fn = gateway.c
        returnResponse(txn);
    }
    else
    {
        // next_fn = gateway.c
        log_warn("productHandler doesn't know what to do for HOP %u.", txn->hop_count);
        returnResponse(txn);
    }
    return;
}

static void addToCartHandler(struct http_transaction *txn)
{
    log_debug("Call addToCartHandler ### Hop: %u", txn->hop_count);
    //log_info("Call addToCartHandler ### Hop: %u", txn->hop_count);
    
    if (txn->hop_count == 0)
    {
        // next_fn = productcatalog.c
        getProduct(txn);
        txn->productViewCntr = 0;
    }
    else if (txn->hop_count == 1)
    {
        // next_fn = cart.c
        insertCart(txn);
    }
    else if (txn->hop_count == 2)
    {
        // next_fn = gateway.c
        returnResponse(txn);
    }
    else
    {
        // next_fn = gateway.c
        log_debug("addToCartHandler doesn't know what to do for HOP %u.", txn->hop_count);
        returnResponse(txn);
    }
}

static void viewCartHandler(struct http_transaction *txn)
{
    log_debug("Call viewCartHandler ### Hop: %u", txn->hop_count);
    //log_info("Call viewCartHandler ### Hop: %u", txn->hop_count);
    
    if (txn->hop_count == 0)
    {
        // next_fn = currency.c
        getCurrencies(txn);
    }
    else if (txn->hop_count == 1)
    {
        // next_fn = cart.c
        getCart(txn);
        txn->cartItemViewCntr = 0;
        strcpy(txn->total_price.CurrencyCode, defaultCurrency);
    }
    else if (txn->hop_count == 2)
    {
        // next_fn = recommendations.c 
        getRecommendations(txn);
    }
    else if (txn->hop_count == 3)
    {
        // next_fn = shipping.c 
        getShippingQuote(txn);
    }
    else if (txn->hop_count == 4)
    {
        // next_fn = currency.c 
        convertCurrencyOfShippingQuote(txn);
        if (txn->get_quote_response.conversion_flag == true)
        {
            // next_fn = productcatalog.c
            getCartItemInfo(txn);
            txn->hop_count++;
        }
        else
        {
            log_debug("Set get_quote_response.conversion_flag as true");
            txn->get_quote_response.conversion_flag = true;
        }
    }
    else if (txn->hop_count == 5)
    {
        // next_fn = productcatalog.c
        getCartItemInfo(txn);
    }
    else if (txn->hop_count == 6)
    {
        // next_fn = currency.c 
        convertCurrencyOfCart(txn);
    }
    else
    {
        // next_fn = gateway.c
        log_debug("viewCartHandler doesn't know what to do for HOP %u.", txn->hop_count);
        returnResponse(txn);
    }
}

static void PlaceOrder(struct http_transaction *txn)
{
    parsePlaceOrderRequest(txn);
    // PrintPlaceOrderRequest(txn);

    strcpy(txn->rpc_handler, "PlaceOrder");
   
    //if(txn->caller_fn != FRONTEND) 
    	txn->caller_fn = FRONTEND;
    //if(txn->next_fn != CHECKOUT_SVC)
    	txn->next_fn = CHECKOUT_SVC;

    //log_info("caller_fn:%d | next_fn:%d", txn->caller_nf, txn->next_fn);
    
    txn->hop_count++;
    txn->checkoutsvc_hop_cnt = 0;

}

static void placeOrderHandler(struct http_transaction *txn)
{
    log_debug("Call placeOrderHandler ### Hop: %u", txn->hop_count);
    //log_info("Call placeOrderHandler ### Hop: %u", txn->hop_count);

    if (txn->hop_count == 0)
    {
        // next_fn = checkout.c
        PlaceOrder(txn);
    }
    else if (txn->hop_count == 1)
    {
        // next_fn = recommendations.c
        getRecommendations(txn);
    }
    else if (txn->hop_count == 2)
    {
        // next_fn = currency.c
        getCurrencies(txn);
    }
    else if (txn->hop_count == 3)
    {
        // next_fn = gateway.c 
        returnResponse(txn);
    }
    else
    {
        log_debug("placeOrderHandler doesn't know what to do for HOP %u.", txn->hop_count);
        returnResponse(txn);
    }
}

static void httpRequestDispatcher(struct http_transaction *txn)
{

    char *req = txn->request;
    // log_debug("Receive one msg: %s", req);
    
    // Requisicao de checkout
    if (strstr(req, "/1/cart/checkout") != NULL)
    //if (strstr(req, "/6/cart/checkout") != NULL)
    {
        // next_fn = checkout.c
        // next_fn = recommendations.c
        // next_fn = currency.c
        // next_fn = gateway.c
        placeOrderHandler(txn);
    }
    else if (strstr(req, "/1/cart") != NULL)
    //else if (strstr(req, "/4/cart") != NULL || strstr(req, "/5/cart"))
    {
        if (strstr(req, "GET"))
        {
            // next_fn = currency.c 
            // next_fn = cart.c
            // next_fn = recommendations.c
            // next_fn = shipping.c
            // next_fn = productcatalog.c
            viewCartHandler(txn);
        }
        else if (strstr(req, "POST"))
        {
            // next_fn = productcatalag.c 
            // next_fn = cart.c
            // next_fn = gateway.c
            addToCartHandler(txn);
        }
        else
        {
            log_debug("No handler found in frontend: %s", req);
        }
    }
    else if (strstr(req, "/1/product") != NULL)
    //else if (strstr(req, "/3/product") != NULL)
    {
        // next_fn = productcatalog.c
        // next_fn = currency.c
        // next_fn = cart.c
        // next_fn = recommendations.c
        // next_fn = ad.c
        // next_fn = gateway.c
        productHandler(txn);
    }
    else if (strstr(req, "/1/setCurrency") != NULL)
    //else if (strstr(req, "/2/setCurrency") != NULL)
    {
        // next_fn = gateway.c 
        setCurrencyHandler(txn);
    }
    else if (strstr(req, "/1") != NULL)
    {
        // next_fn = currency.c 
        // next_fn = productcatalog.c
        // next_fn = ad.c
        // next_fn = cart.c
        // next_fn = gateway.c
        homeHandler(txn);
    }
    else
    {
        log_debug("Unknown handler. Check your HTTP Query, human!: %s", req);
        returnResponse(txn);
    }

    return;
}

static void *nf_worker(void *arg){
    //struct http_transaction *txn = NULL;
    struct http_transaction *txn;
    ssize_t bytes_written;
    ssize_t bytes_read;
    uint8_t index;

    /* TODO: Careful with this pointer as it may point to a stack */
    index = (uint64_t)arg;

    while (1){

        bytes_read = read(pipefd_rx[index][0], &txn, sizeof(struct http_transaction *));
        if (unlikely(bytes_read == -1)){
            log_error("read() error: %s", strerror(errno));
            return NULL;
        }
        // log_debug("Receive one msg: %s", txn->request);
        //log_info("Receive one msg: %s", txn->request);
        // Trata a requisicao e escreve as informacoes para o proximo container
        httpRequestDispatcher(txn);

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
        if (unlikely(txn == NULL)){
            log_error("io_rx() error");
            return NULL;
        }


	//txn = sigshared_mempool_access(txn, addr);
	if(unlikely(txn == NULL)){
		printf("==email== ERRO mempool_access retornou NULL\n");
		return NULL;
	}


        bytes_written = write(pipefd_rx[i][1], &txn, sizeof(struct http_transaction *));
        if (unlikely(bytes_written == -1))
        {
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

static void *nf_tx(void *arg){

    struct epoll_event event[UINT8_MAX]; /* TODO: Use Macro */
    //struct http_transaction *txn = NULL;
    struct http_transaction *txn;
    ssize_t bytes_read;
    uint8_t i;
    int n_fds;
    int epfd;
    int ret;
    int ret_io;

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

    while (1){

        n_fds = epoll_wait(epfd, event, sigshared_cfg->nf[fn_id - 1].n_threads, -1);
        if (unlikely(n_fds == -1)){

            log_error("epoll_wait() error: %s", strerror(errno));
            return NULL;
        }

        for (i = 0; i < n_fds; i++){

            bytes_read = read(event[i].data.fd, &txn, sizeof(struct http_transaction *));
            if (unlikely(bytes_read == -1)){
                log_error("read() error: %s", strerror(errno));
                return NULL;
            }

            //log_debug("Route id: %u, Hop Count %u, Next Hop: %u, Next Fn: %u, Caller Fn: %s (#%u), RPC Handler: %s()", txn->route_id, txn->hop_count, sigshared_cfg->route[txn->route_id].hop[txn->hop_count], txn->next_fn, txn->caller_nf, txn->caller_fn, txn->rpc_handler);
            //log_info("Route id: %u, Hop Count %u, Next Hop: %u, Next Fn: %u, Caller Fn: %s (#%u), RPC Handler: %s()", txn->route_id, txn->hop_count, sigshared_cfg->route[txn->route_id].hop[txn->hop_count], txn->next_fn, txn->caller_nf, txn->caller_fn, txn->rpc_handler);

            ret_io = io_tx_matriz(txn->addr, txn->next_fn, &mapa_fd, pid, matriz, matriz[txn->next_fn][1]);
            if (unlikely(ret_io == -1)){
                log_error("io_tx() error");
                return NULL;
            }
            //log_info("(ADDR TX:%ld), Route id: %u, Next Fn: %u, Caller Fn: %s (#%u) ", txn->addr, txn->route_id, txn->next_fn, txn->caller_nf, txn->caller_fn);
            //log_info("(ADDR TX:%ld), HOP: %u, Next Fn: %u, Caller Fn: %s (#%u) ", txn->addr, txn->hop_count, txn->next_fn, txn->caller_nf, txn->caller_fn);
        }
    }

    return NULL;
}

/* TODO: Cleanup on errors */
static int nf(uint8_t nf_id){
    //const struct rte_memzone *memzone = NULL;
    pthread_t thread_worker[UINT8_MAX];
    pthread_t thread_rx;
    pthread_t thread_tx;
    uint8_t i;
    int ret;

    fn_id = nf_id;

    //int pid = getpid();

    matriz[nf_id][1] = pid;
    if(unlikely( sigshared_update_map("mapa_sinal", fn_id, pid, &mapa_fd) < 0 ) ){
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

    // IO_RX()
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

    // WORKERS
    for (i = 0; i < sigshared_cfg->nf[fn_id - 1].n_threads; i++){
        ret = pthread_create(&thread_worker[i], NULL, &nf_worker, (void *)(uint64_t)i);
        if (unlikely(ret != 0))
        {
            log_error("pthread_create() error: %s", strerror(ret));
            return -1;
        }
    }

    /*********Espera pelas workers*********/
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

    ret = io_exit();
    if (unlikely(ret == -1))
    {
        log_error("io_exit() error");
        return -1;
    }

    return 0;
}
/***************************************************************************/
void segfault_handler(int sig) {
    //void *array[20];
    //size_t size;

    //// Get the backtrace addresses
    //size = backtrace(array, 20);

    //fprintf(stderr, "\n[CRASH] Caught signal %d (Segmentation fault)\n", sig);
    //backtrace_symbols_fd(array, size, STDERR_FILENO);

    //_exit(1); // exit immediately, skip cleanup

    void *trace[32];
    int size = backtrace(trace, 32);
    
    fprintf(stderr, "\n[CRASH] Segmentation fault (signal %d)\n", sig);
    backtrace_symbols_fd(trace, size, STDERR_FILENO);
    fflush(stderr);
    
    _exit(1);
}

/***************************************************************************/
int main(int argc, char **argv){

    log_set_level_from_env();
    log_set_level(LOG_INFO);

    //signal(SIGSEGV, segfault_handler);
    //signal(SIGBUS, segfault_handler);
    //signal(SIGABRT, segfault_handler);

    uint8_t nf_id;
    int ret;

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

    sigemptyset(&set);       
    sigaddset(&set, SIGRTMIN+1); 
    sigprocmask(SIG_BLOCK, &set, NULL);

    pid = getpid();

    char settar_cpuf[30];

    printf("Atribuindo processo para a CPU 3...\n");
    sprintf(settar_cpuf, "taskset -cp 3 %d", getpid());
    int ret_sys = system(settar_cpuf);
    if( ret_sys == -1 || ret_sys == 127 ){
            log_error("Erro ao settar CPU");
            exit(1);
    }

    //cpu_set_t cpu_aff;
    //CPU_ZERO(&cpu_aff);
    //CPU_SET(3, &cpu_aff);


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
    printf("Erro ao inicializar nf()\n");
    //rte_eal_cleanup();
//error_0:
//    return 1;
}

/*
 * This file has been simplified and modified from the original project SPRIGHT for the purposes of test and experiment the latency impact of real-time signals in microsservices.
 *
 */



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

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <libconfig.h>

#include <stdlib.h>

//#include <rte_branch_prediction.h>
//#include <rte_eal.h>
//#include <rte_errno.h>
//#include <rte_lcore.h>
//#include <rte_mempool.h>
//#include <rte_memzone.h>

#include "sigshared.h"



#include "./include/http.h"
#include "./include/io.h"
#include "./log/log.h"
#include "./include/spright.h"
#include "./include/utility.h"




static void cfg_print(void)
{
    uint8_t i;
    uint8_t j;

    //printf("Name: %s\n", cfg->name);
    printf("Name: %s\n", sigshared_cfg->name);

    //printf("Number of Tenants: %d\n", cfg->n_tenants);
    printf("Number of Tenants: %d\n", sigshared_cfg->n_tenants);
    printf("Tenants:\n");
    //for (i = 0; i < cfg->n_tenants; i++)
    for (i = 0; i < sigshared_cfg->n_tenants; i++)
    {
        printf("\tID: %hhu\n", i);
        //printf("\tWeight: %d\n", cfg->tenants[i].weight);
        printf("\tWeight: %d\n", sigshared_cfg->tenants[i].weight);
        printf("\n");
    }

    //printf("Number of NFs: %hhu\n", cfg->n_nfs);
    printf("Number of NFs: %hhu\n", sigshared_cfg->n_nfs);
    printf("NFs:\n");
    //for (i = 0; i < cfg->n_nfs; i++)
    for (i = 0; i < sigshared_cfg->n_nfs; i++)
    {
        printf("\tID: %hhu\n", i + 1);
        printf("\tName: %s\n",               sigshared_cfg->nf[i].name             /* cfg->nf[i].name*/);
        printf("\tNumber of Threads: %hhu\n",sigshared_cfg->nf[i].n_threads        /* cfg->nf[i].n_threads*/);
        printf("\tParams:\n");
        printf("\t\tmemory_mb: %hhu\n",      sigshared_cfg->nf[i].param.memory_mb  /* cfg->nf[i].param.memory_mb*/);
        printf("\t\tsleep_ns: %u\n",         sigshared_cfg->nf[i].param.sleep_ns   /* cfg->nf[i].param.sleep_ns*/);
        printf("\t\tcompute: %u\n",          sigshared_cfg->nf[i].param.compute    /* cfg->nf[i].param.compute*/);
        printf("\tNode: %u\n",               sigshared_cfg->nf[i].node             /* cfg->nf[i].node*/);
        printf("\n");
    }

    //printf("Number of Routes: %hhu\n", cfg->n_routes);
    printf("Number of Routes: %hhu\n", sigshared_cfg->n_routes);
    printf("Routes:\n");
    //for (i = 0; i < cfg->n_routes; i++)
    for (i = 0; i < sigshared_cfg->n_routes; i++)
    {
        printf("\tID: %hhu\n", i);
        //printf("\tName: %s\n", cfg->route[i].name);
        printf("\tName: %s\n", sigshared_cfg->route[i].name);
        //printf("\tLength = %hhu\n", cfg->route[i].length);
        printf("\tLength = %hhu\n", sigshared_cfg->route[i].length);
        //if (cfg->route[i].length > 0)
        if ( sigshared_cfg->route[i].length > 0 )
        {
            printf("\tHops = [");
            //for (j = 0; j < cfg->route[i].length; j++)
            for (j = 0; j < sigshared_cfg->route[i].length; j++)
            {
                //printf("%hhu ", cfg->route[i].hop[j]);
                printf("%hhu ", sigshared_cfg->route[i].hop[j]);
            }
            printf("\b]\n");
        }
        printf("\n");
    }

    //printf("Number of Nodes: %hhu\n", cfg->n_nodes);
    printf("Number of Nodes: %hhu\n", sigshared_cfg->n_nodes);
    //printf("Local Node Index: %u\n", cfg->local_node_idx);
    printf("Local Node Index: %u\n", sigshared_cfg->local_node_idx);
    printf("Nodes:\n");
    //for (i = 0; i < cfg->n_nodes; i++)
    for (i = 0; i < sigshared_cfg->n_nodes; i++)
    {
        printf("\tID: %hhu\n", i);
        printf("\tHostname: %s\n",   sigshared_cfg->nodes[i].hostname    /*cfg->nodes[i].hostname */  );
        printf("\tIP Address: %s\n", sigshared_cfg->nodes[i].ip_address  /*cfg->nodes[i].ip_address */  );
        printf("\tPort = %u\n",      sigshared_cfg->nodes[i].port        /*cfg->nodes[i].port       */  );
        printf("\n");
    }

    print_rt_table();
}

static int cfg_init(char *cfg_file)
{
    config_setting_t *subsubsetting = NULL;
    config_setting_t *subsetting = NULL;
    config_setting_t *setting = NULL;
    
    const char *name = NULL;
    const char *hostname = NULL;
    const char *ip_address = NULL;
    
    config_t config; // config passado para a func config_init()
    
    int value;
    int ret;
    int id;
    int n;
    int m;
    int i;
    int j;
    int node;
    int port;
    int weight;

    /* TODO: Change "flags" argument */
    //cfg->mempool = rte_mempool_create(MEMPOOL_NAME, N_MEMPOOL_ELEMENTS, sizeof(struct http_transaction), 0, 0, NULL,
    //                                  NULL, NULL, NULL, rte_socket_id(), 0);
    //if (unlikely(cfg->mempool == NULL))
    //if (unlikely(mempool == NULL)){
    //    //log_error("rte_mempool_create() error: %s", rte_strerror(rte_errno));
    //    log_error("mempool eh NULL error");
    //    goto error_0;
    //}

    // Configuracoes dos ambientes com func propria para isso
    config_init(&config);

    ret = config_read_file(&config, cfg_file);
    if (unlikely(ret == CONFIG_FALSE))
    {
        log_error("config_read_file() error: line %d: %s", config_error_line(&config), config_error_text(&config));
        goto error_1;
    }

    ret = config_lookup_string(&config, "name", &name);
    if (unlikely(ret == CONFIG_FALSE))
    {
        /* TODO: Error message */
        goto error_1;
    }

    //strcpy(cfg->name, name);
    strcpy(sigshared_cfg->name, name);

    setting = config_lookup(&config, "nfs");
    if (unlikely(setting == NULL))
    {
        /* TODO: Error message */
        goto error_1;
    }

    ret = config_setting_is_list(setting);
    if (unlikely(ret == CONFIG_FALSE))
    {
        /* TODO: Error message */
        goto error_1;
    }

    n = config_setting_length(setting);
    //cfg->n_nfs = n;
    sigshared_cfg->n_nfs = n;

    for (i = 0; i < n; i++)
    {
        subsetting = config_setting_get_elem(setting, i);
        if (unlikely(subsetting == NULL))
        {
            /* TODO: Error message */
            goto error_1;
        }

        ret = config_setting_is_group(subsetting);
        if (unlikely(ret == CONFIG_FALSE))
        {
            /* TODO: Error message */
            goto error_1;
        }

        ret = config_setting_lookup_int(subsetting, "id", &id);
        if (unlikely(ret == CONFIG_FALSE))
        {
            /* TODO: Error message */
            goto error_1;
        }

        ret = config_setting_lookup_string(subsetting, "name", &name);
        if (unlikely(ret == CONFIG_FALSE))
        {
            /* TODO: Error message */
            goto error_1;
        }

        //strcpy(cfg->nf[id - 1].name, name);
        strcpy(sigshared_cfg->nf[id - 1].name, name);

        ret = config_setting_lookup_int(subsetting, "n_threads", &value);
        if (unlikely(ret == CONFIG_FALSE))
        {
            /* TODO: Error message */
            goto error_1;
        }

        //cfg->nf[id - 1].n_threads = value;
        sigshared_cfg->nf[id - 1].n_threads = value;

        subsubsetting = config_setting_lookup(subsetting, "params");
        if (unlikely(subsubsetting == NULL))
        {
            /* TODO: Error message */
            goto error_1;
        }

        ret = config_setting_is_group(subsubsetting);
        if (unlikely(ret == CONFIG_FALSE))
        {
            /* TODO: Error message */
            goto error_1;
        }

        ret = config_setting_lookup_int(subsubsetting, "memory_mb", &value);
        if (unlikely(ret == CONFIG_FALSE))
        {
            /* TODO: Error message */
            goto error_1;
        }

        //cfg->nf[id - 1].param.memory_mb = value;
        sigshared_cfg->nf[id - 1].param.memory_mb = value;

        ret = config_setting_lookup_int(subsubsetting, "sleep_ns", &value);
        if (unlikely(ret == CONFIG_FALSE))
        {
            /* TODO: Error message */
            goto error_1;
        }

        //cfg->nf[id - 1].param.sleep_ns = value;
        sigshared_cfg->nf[id - 1].param.sleep_ns = value;

        ret = config_setting_lookup_int(subsubsetting, "compute", &value);
        if (unlikely(ret == CONFIG_FALSE))
        {
            /* TODO: Error message */
            goto error_1;
        }

        //cfg->nf[id - 1].param.compute = value;
        sigshared_cfg->nf[id - 1].param.compute = value;

        ret = config_setting_lookup_int(subsetting, "node", &node);
        if (unlikely(ret == CONFIG_FALSE))
        {
            log_info("Set default node as 0.");
            node = 0;
        }

        //cfg->nf[id - 1].node = node;
        sigshared_cfg->nf[id - 1].node = node;
        set_node(id, node);
    }

    setting = config_lookup(&config, "routes");
    if (unlikely(setting == NULL))
    {
        /* TODO: Error message */
        goto error_1;
    }

    ret = config_setting_is_list(setting);
    if (unlikely(ret == CONFIG_FALSE))
    {
        /* TODO: Error message */
        goto error_1;
    }

    n = config_setting_length(setting);
    //cfg->n_routes = n + 1;
    sigshared_cfg->n_routes = n + 1;

    //strcpy(cfg->route[0].name, "Default");
    strcpy(sigshared_cfg->route[0].name, "Default");
    //cfg->route[0].length = 0;
    sigshared_cfg->route[0].length = 0;

    for (i = 0; i < n; i++)
    {
        subsetting = config_setting_get_elem(setting, i);
        if (unlikely(subsetting == NULL))
        {
            /* TODO: Error message */
            goto error_1;
        }

        ret = config_setting_is_group(subsetting);
        if (unlikely(ret == CONFIG_FALSE))
        {
            /* TODO: Error message */
            goto error_1;
        }

        ret = config_setting_lookup_int(subsetting, "id", &id);
        if (unlikely(ret == CONFIG_FALSE))
        {
            /* TODO: Error message */
            goto error_1;
        }
        else if (unlikely(id == 0))
        {
            /* TODO: Error message */
            goto error_1;
        }

        ret = config_setting_lookup_string(subsetting, "name", &name);
        if (unlikely(ret == CONFIG_FALSE))
        {
            /* TODO: Error message */
            goto error_1;
        }

        //strcpy(cfg->route[id].name, name);
        strcpy(sigshared_cfg->route[id].name, name);

        subsubsetting = config_setting_lookup(subsetting, "hops");
        if (unlikely(subsubsetting == NULL))
        {
            /* TODO: Error message */
            goto error_1;
        }

        ret = config_setting_is_array(subsubsetting);
        if (unlikely(ret == CONFIG_FALSE))
        {
            /* TODO: Error message */
            goto error_1;
        }

        m = config_setting_length(subsubsetting);
        //cfg->route[id].length = m;
        sigshared_cfg->route[id].length = m;

        for (j = 0; j < m; j++)
        {
            value = config_setting_get_int_elem(subsubsetting, j);
            //cfg->route[id].hop[j] = value;
            sigshared_cfg->route[id].hop[j] = value;
        }
    }

    //char local_hostname[HOST_NAME_MAX];
    char local_hostname[256];
    if (gethostname(local_hostname, sizeof(local_hostname)) == -1)
    {
        log_error("gethostname() failed");
        goto error_1;
    }
    int is_hostname_matched = -1;

    setting = config_lookup(&config, "nodes");
    if (unlikely(setting == NULL))
    {
        log_warn("Nodes configuration is missing.");
        goto error_2;
    }

    ret = config_setting_is_list(setting);
    if (unlikely(ret == CONFIG_FALSE))
    {
        log_warn("Nodes configuration is missing.");
        goto error_2;
    }

    n = config_setting_length(setting);
    //cfg->n_nodes = n;
    sigshared_cfg->n_nodes = n;

    for (i = 0; i < n; i++)
    {
        subsetting = config_setting_get_elem(setting, i);
        if (unlikely(subsetting == NULL))
        {
            log_warn("Node configuration is missing.");
            goto error_2;
        }

        ret = config_setting_is_group(subsetting);
        if (unlikely(ret == CONFIG_FALSE))
        {
            log_warn("Node configuration is missing.");
            goto error_2;
        }

        ret = config_setting_lookup_int(subsetting, "id", &id);
        if (unlikely(ret == CONFIG_FALSE))
        {
            log_warn("Node ID is missing.");
            goto error_2;
        }

        ret = config_setting_lookup_string(subsetting, "hostname", &hostname);
        if (unlikely(ret == CONFIG_FALSE))
        {
            log_warn("Node hostname is missing.");
            goto error_2;
        }

        //strcpy(cfg->nodes[id].hostname, hostname);
        strcpy(sigshared_cfg->nodes[id].hostname, hostname);

        /* Compare the hostnames */
        //if (strcmp(local_hostname, cfg->nodes[id].hostname) == 0)
        if (strcmp(local_hostname, sigshared_cfg->nodes[id].hostname) == 0)
        {
            //cfg->local_node_idx = i;
            sigshared_cfg->local_node_idx = i;
            is_hostname_matched = 1;
            log_info("Hostnames match: %s, node index: %u", local_hostname, i);
        }
        else
        {
            log_debug("Hostnames do not match. Got: %s, Expected: %s", local_hostname, hostname);
        }

        ret = config_setting_lookup_string(subsetting, "ip_address", &ip_address);
        if (unlikely(ret == CONFIG_FALSE))
        {
            log_warn("Node ip_address is missing.");
            goto error_2;
        }

        //strcpy(cfg->nodes[id].ip_address, ip_address);
        strcpy(sigshared_cfg->nodes[id].ip_address, ip_address);

        ret = config_setting_lookup_int(subsetting, "port", &port);
        if (unlikely(ret == CONFIG_FALSE))
        {
            log_warn("Node port is missing.");
            goto error_2;
        }

        //cfg->nodes[id].port = port;
        sigshared_cfg->nodes[id].port = port;
    }

    setting = config_lookup(&config, "tenants");
    if (unlikely(setting == NULL))
    {
        log_error("Tenants configuration is required.");
        goto error_1;
    }

    ret = config_setting_is_list(setting);
    if (unlikely(ret == CONFIG_FALSE))
    {
        log_error("Tenants configuration is required.");
        goto error_1;
    }

    n = config_setting_length(setting);
    //cfg->n_tenants = n;
    sigshared_cfg->n_tenants = n;

    for (i = 0; i < n; i++)
    {
        subsetting = config_setting_get_elem(setting, i);
        if (unlikely(subsetting == NULL))
        {
            log_error("Tenant-%d's configuration is required.", i);
            goto error_1;
        }

        ret = config_setting_is_group(subsetting);
        if (unlikely(ret == CONFIG_FALSE))
        {
            log_error("Tenant-%d's configuration is required.", i);
            goto error_1;
        }

        ret = config_setting_lookup_int(subsetting, "id", &id);
        if (unlikely(ret == CONFIG_FALSE))
        {
            log_error("Tenant-%d's ID is required.", i);
            goto error_1;
        }

        ret = config_setting_lookup_int(subsetting, "weight", &weight);
        if (unlikely(ret == CONFIG_FALSE))
        {
            log_error("Tenant-%d's weight is required.", i);
            goto error_1;
        }

        //cfg->tenants[id].weight = weight;
        sigshared_cfg->tenants[id].weight = weight;
    }

    if (is_hostname_matched == -1)
    {
        log_error("No matched hostname in %s", cfg_file);
        goto error_1;
    }

error_2:
    config_destroy(&config);
    cfg_print();

    return 0;

error_1:
    config_destroy(&config);
    //rte_mempool_free(cfg->mempool);
//error_0:
//    return -1;
     return 0;
}

static int cfg_exit(void)
{
    //rte_mempool_free(cfg->mempool);
    shm_unlink(SIGSHARED_NAME);
    return 0;
}

static int shm_mgr(char *cfg_file)
{
    //const struct rte_memzone *memzone = NULL;
    int ret;

    fn_id = -1;


    

    //memzone = rte_memzone_reserve(MEMZONE_NAME, sizeof(*cfg), rte_socket_id(), 0);
    //if (unlikely(memzone == NULL))
    //{
    //    log_error("rte_memzone_reserve() error: %s", rte_strerror(rte_errno));
    //    goto error_0;
    //}

    //memset(memzone->addr, 0U, sizeof(*cfg));

    //cfg = memzone->addr;

    ret = cfg_init(cfg_file);
    if (unlikely(ret == -1))
    {
        log_error("cfg_init() error");
        goto error_1;
    }

    // fd_id = -1 entao io_init() retorna sem fazer nada
    //ret = io_init();
    //if (unlikely(ret == -1))
    //{
    //    log_error("io_init() error");
    //    goto error_2;
    //}


    //char *sigshared_path;
    //if ((sigshared_path = getcwd(NULL, 0)) == NULL) {
    //    perror("Erro ao pegar o diretorio");
    //} else {
    //    printf("Diretorio do SIGSHARED: %s\n", sigshared_path);
    //    //free(buffer); // Remember to free the allocated memory
    //}


    char *temp = getenv("SIGSHARED");
    char path[300];
    sprintf(path, "%s/dados", temp);
    printf("###\n%s\n", path);


    cfg_print();

    /* TODO: Exit loop on interrupt */
    while (1)
    {
        sleep(30);
    }

    ret = io_exit();
    if (unlikely(ret == -1))
    {
        log_error("io_exit() error");
        goto error_2;
    }

    ret = cfg_exit();
    if (unlikely(ret == -1))
    {
        log_error("cfg_exit() error");
        goto error_1;
    }

    //ret = rte_memzone_free(memzone);
    //if (unlikely(ret < 0))
    //{
    //    log_error("rte_memzone_free() error: %s", rte_strerror(-ret));
    //    goto error_0;
    //}

    return 0;

error_2:
    cfg_exit();
error_1:
    printf("Erro ao inicializar cfg_init()\n");
    return -1;
    //rte_memzone_free(memzone);
//error_0:
//    return -1;
}

int main(int argc, char **argv)
{
    int ret;

    log_set_level(LOG_INFO);

    if (argc < 2){
    	printf("Erro ao passar os argumentos\n");
	goto error_1;
    }

    printf("ARGC: %d\n", argc);
    printf("ARGV[0]: %s\n", argv[7]);
    printf("ARGV[8]: %s\n", argv[8]);

    // Sigshared
    // 65K posicoes de tamanho da struct http_transaction
   
    sigshared_ptr = sigshared_create_mem();
    if (sigshared_ptr == NULL){
        printf("ERRO AO CRIAR MEMORIA COMPARTILHADA\n");
        return 1;
    }

    sigshared_cfg = sigshared_cfg_mem();
    if (sigshared_cfg == NULL){
        printf("ERRO AO CRIAR MEMORIA DA CONFIG\n");
        return 1;
    }

    ringbuff = sigshared_mempool_create();
    if(ringbuff == NULL){
    	perror("==ERRO== erro ao criar ringbuffer");
	return 1;
    }

    char *sigshared_path;

    // Option 2: Let getcwd allocate the buffer (more robust)
    if ((sigshared_path = getcwd(NULL, 0)) == NULL) {
        perror("Erro ao pegar o diretorio");
    } else {
        printf("Diretorio do SIGSHARED: %s\n", sigshared_path);
        //free(buffer); // Remember to free the allocated memory
    }

    if (setenv("SIGSHARED", sigshared_path, 0) == 0) {
        printf("Environment variable MY_VARIABLE attempted to be set without overwrite.\n");
    } else {
        perror("Failed to set environment variable MY_VARIABLE without overwrite");
    }

    //ret = rte_eal_init(argc, argv);
    //if (unlikely(ret == -1))
    //{
    //    log_error("rte_eal_init() error: %s", rte_strerror(rte_errno));
    //    goto error_0;
    //}

    //argc -= ret;
    //argv += ret;

    if (unlikely(argc == 1))
    {
        log_error("Configuration file not provided");
        goto error_1;
    }

    //ret = shm_mgr(argv[1]);
    ret = shm_mgr(argv[8]);
    if (unlikely(ret == -1))
    {
        log_error("shm_mgr() error");
        goto error_1;
    }

    //ret = rte_eal_cleanup();
    //if (unlikely(ret < 0))
    //{
    //    log_error("rte_eal_cleanup() error: %s", rte_strerror(-ret));
    //    goto error_0;
    //}

    return 0;

error_1:
    printf("Erro ao inicializar nf()\n%s\n", argv[8]);
    //rte_eal_cleanup();
//error_0:
//    return 1;
}

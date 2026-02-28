#!/bin/bash

for i in {2 ..29};
do
    if [ ! -d "locust_worker_${i}/" ]; then
        echo "locust_worker_${j}/ DOES NOT exists."
        exit 1
    else
        cat $STAT_PATH/locust_worker_${j}/resp_time_node1.ricardo-sig.aos-ufmg-dcc*.csv >> $STAT_PATH/latency_of_each_req_stats_${ALTERNATIVE}.csv
    fi
done



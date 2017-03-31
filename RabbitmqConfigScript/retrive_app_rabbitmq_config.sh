#!/bin/bash

docker run -itd --name rabbitmq_temp -p 15671:15672 -e RABBITMQ_DEFAULT_USER=admin -e RABBITMQ_DEFAULT_PASS=admin123 rabbitmq:3.6.6-management

sleep 8s

./rabbit-rhea-config.sh

rabbitmqadmin export rabbit-rhea-config

docker stop rabbitmq_temp

docker rm rabbitmq_temp

#!/bin/bash

# ~/.rabbitmqadmin.conf
# [default]
# hostname = 172.16.22.74
# port = 15672
# username = admin
# password = admin123

#==================== declare users ====================
# administrator
# rabbitmqadmin declare user name=admin password=admin tags=administrator 

# application users
rabbitmqadmin declare user name=rhea password=rhea tags=management

#==================== declare virtual hosts ====================
rabbitmqadmin declare vhost name=fincloud

#==================== declare permissions ====================
rabbitmqadmin declare permission vhost=fincloud user=rhea configure="^(fincloud\.queue\.notification\.(sms|email))|(fincloud\.exchange\.notification)$" write="^(fincloud\.queue\.notification\.(sms|email))|(fincloud\.exchange\.notification)$" read="^(fincloud\.queue\.notification\.(sms|email))|(fincloud\.exchange\.notification)$"
rabbitmqadmin declare permission vhost=fincloud user=admin configure=.* write=.* read=.*

#==================== declare exchanges ====================
# exchange for sms
rabbitmqadmin -N rhea --vhost=fincloud declare exchange name="fincloud.exchange.notification" type=topic durable=true

#==================== declare queues ====================
# queue for sending sms
rabbitmqadmin -N rhea --vhost=fincloud declare queue name="fincloud.queue.notification.sms" durable=true
# queue for sending email
rabbitmqadmin -N rhea --vhost=fincloud declare queue name="fincloud.queue.notification.email" durable=true

#==================== declare bindings ====================
rabbitmqadmin -N rhea --vhost=fincloud declare binding source="fincloud.exchange.notification" destination="fincloud.queue.notification.sms" routing_key="fincloud.routingKey.sms"
rabbitmqadmin -N rhea --vhost=fincloud declare binding source="fincloud.exchange.notification" destination="fincloud.queue.notification.email" routing_key="fincloud.routingKey.email"

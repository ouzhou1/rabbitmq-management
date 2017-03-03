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
rabbitmqadmin declare user name=demeter password=demeter tags=management

#==================== declare virtual hosts ====================
rabbitmqadmin declare vhost name=fincloud

#==================== declare permissions ====================
rabbitmqadmin declare permission vhost=fincloud user=demeter configure="fincloud\.exchange\.(notification|oplog|alert)|fincloud\.queue\.(notification\.(sms|email)|oplog|alert)" write="fincloud\.exchange\.(notification|oplog|alert)|fincloud\.queue\.(notification\.(sms|email)|oplog|alert)" read="fincloud\.exchange\.(notification|oplog|alert)|fincloud\.queue\.(notification\.(sms|email)|oplog|alert)"
rabbitmqadmin declare permission vhost=fincloud user=admin configure=.* write=.* read=.*
 
#==================== declare exchanges ====================
# exchange for sms
rabbitmqadmin -N demeter --vhost=fincloud declare exchange name="fincloud.exchange.notification" type=topic durable=true
# exchange for operation logs
rabbitmqadmin -N demeter --vhost=fincloud declare exchange name="fincloud.exchange.oplog" type=topic durable=true
# exchange for alert
rabbitmqadmin -N demeter --vhost=fincloud declare exchange name="fincloud.exchange.alert" type=topic durable=true

#==================== declare queues ====================
# queue for sending sms
rabbitmqadmin -N demeter --vhost=fincloud declare queue name="fincloud.queue.notification.sms" durable=true
# queue for sending email
rabbitmqadmin -N demeter --vhost=fincloud declare queue name="fincloud.queue.notification.email" durable=true
# queue for operation logs
rabbitmqadmin -N demeter --vhost=fincloud declare queue name="fincloud.queue.oplog" durable=true
# queue for alert
rabbitmqadmin -N demeter --vhost=fincloud declare queue name="fincloud.queue.alert" durable=true

#==================== declare bindings ====================
rabbitmqadmin -N demeter --vhost=fincloud declare binding source="fincloud.exchange.notification" destination="fincloud.queue.notification.sms" routing_key=fincloud.routingKey.sms
rabbitmqadmin -N demeter --vhost=fincloud declare binding source="fincloud.exchange.notification" destination="fincloud.queue.notification.email" routing_key=fincloud.routingKey.email
rabbitmqadmin -N demeter --vhost=fincloud declare binding source="fincloud.exchange.oplog" destination="fincloud.queue.oplog" routing_key=fincloud.routingKey.oplog
rabbitmqadmin -N demeter --vhost=fincloud declare binding source="fincloud.exchange.alert" destination="fincloud.queue.alert" routing_key=fincloud.routingKey.alert

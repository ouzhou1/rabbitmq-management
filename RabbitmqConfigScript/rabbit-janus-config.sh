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
rabbitmqadmin declare user name=janus_platform password=janus_platform tags=management
rabbitmqadmin declare user name=janus_mobile password=janus_mobile tags=management

#==================== declare virtual hosts ====================
rabbitmqadmin declare vhost name=fincloud

#==================== declare permissions ====================
rabbitmqadmin declare permission vhost=fincloud user=janus_mobile configure="^(fincloud\.exchange\.notification)|(fincloud\.queue\.notification\.(sms|email))$" write="^(fincloud\.exchange\.notification)|(fincloud\.queue\.notification\.(sms|email))$" read="^(fincloud\.exchange\.notification)|(fincloud\.queue\.notification\.(sms|email))$"
rabbitmqadmin declare permission vhost=fincloud user=janus_platform configure="^(fincloud\.exchange\.order)|(fincloud\.queue\.orderStatus)$" write="^(fincloud\.exchange\.order)|(fincloud\.queue\.orderStatus)$" read="^(fincloud\.exchange\.order)|(fincloud\.queue\.orderStatus)$"

#==================== declare exchanges ====================
# exchange for order
rabbitmqadmin -N janus_platform --vhost=fincloud declare exchange name="fincloud.exchange.order" type=topic durable=true
# exchange for sms
rabbitmqadmin -N janus_mobile --vhost=fincloud declare exchange name="fincloud.exchange.notification" type=topic durable=true

#==================== declare queues ====================
# queue for order
rabbitmqadmin -N janus_platform --vhost=fincloud declare queue name="fincloud.queue.orderStatus" durable=true

#==================== declare bindings ====================
rabbitmqadmin -N janus_platform --vhost=fincloud declare binding source="fincloud.exchange.order" destination="fincloud.queue.orderStatus" routing_key="fincloud.routingKey.orderStatus"


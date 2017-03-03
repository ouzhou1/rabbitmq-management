#!/bin/bash

# Define content below in ~/.rabbitmqadmin.conf
# [default]
# hostname = 172.16.22.74
# port = 15672
# username = admin
# password = admin123
# [toms]
# hostname = 172.16.22.74
# port = 15672
# username = toms
# password = toms
# [...]
# hostname = 172.16.22.74
# port = 15672
# username = ...
# password = ...

#==================== declare users ====================
# administrator
# rabbitmqadmin declare user name=admin password=admin tags=administrator 

# application users
rabbitmqadmin declare user name=toms password=toms tags=management

#==================== declare virtual hosts ====================
rabbitmqadmin declare vhost name=fincloud

#==================== declare permissions ====================
rabbitmqadmin declare permission vhost=fincloud user=toms configure="^fincloud\.(exchange|queue)\.oplog$" write="^fincloud\.(exchange|queue)\.oplog$" read="^fincloud\.(exchange|queue)\.oplog$"
rabbitmqadmin declare permission vhost=fincloud user=admin configure=.* write=.* read=.*

#==================== declare exchanges ====================
# exchange for operation logs
rabbitmqadmin -N toms --vhost=fincloud declare exchange name="fincloud.exchange.oplog" type=topic durable=true

#==================== declare queues ====================
# queue for operation logs
rabbitmqadmin -N toms --vhost=fincloud declare queue name="fincloud.queue.oplog" durable=true

#==================== declare bindings ====================
rabbitmqadmin -N toms --vhost=fincloud declare binding source="fincloud.exchange.oplog" destination="fincloud.queue.oplog" routing_key="fincloud.routingKey.oplog"


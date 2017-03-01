#!/bin/bash

# Define content below in ~/.rabbitmqadmin.conf
# [default]
# hostname = 172.16.22.74
# port = 15672
# username = admin
# password = admin123
# [apollo]
# hostname = 172.16.22.74
# port = 15672
# username = apollo
# password = apollo
# [...]
# hostname = 172.16.22.74
# port = 15672
# username = ...
# password = ...

#==================== declare users ====================
# administrator
# rabbitmqadmin declare user name=admin password=admin tags=administrator 

# application users
rabbitmqadmin declare user name=apollo password=apollo tags=management

#==================== declare virtual hosts ====================
rabbitmqadmin declare vhost name=fincloud

#==================== declare permissions ====================
rabbitmqadmin -H 172.16.22.74 declare permission vhost=fincloud user=apollo configure="^(fincloud\.queue\.(loanConfirmation|buyBackLoan|orderStatus|cashPaymentLoan))|fincloud\.exchange\.(loan|order|oplog)$" write="^fincloud\.queue\.(loanConfirmation|buyBackLoan|orderStatus|cashPaymentLoan)|fincloud\.exchange\.(loan|order|oplog)$" read="^fincloud\.queue\.(loanConfirmation|buyBackLoan|orderStatus|cashPaymentLoan)|fincloud\.exchange\.(loan|order|oplog)$"

#==================== declare exchanges ====================
# exchange for loan
rabbitmqadmin -N apollo --vhost=fincloud declare exchange name="fincloud.exchange.loan" type=topic durable=true
# exchange for order
rabbitmqadmin -N apollo --vhost=fincloud declare exchange name="fincloud.exchange.order" type=topic durable=true

#==================== declare queues ====================
# queues for loan
rabbitmqadmin -N apollo --vhost=fincloud declare queue name="fincloud.queue.loanConfirmation" durable=true
rabbitmqadmin -N apollo --vhost=fincloud declare queue name="fincloud.queue.buyBackLoan" durable=true
rabbitmqadmin -N apollo --vhost=fincloud declare queue name="fincloud.queue.cashPaymentLoan" durable=true
# queue for order
rabbitmqadmin -N apollo --vhost=fincloud declare queue name="fincloud.queue.orderStatus" durable=true

#==================== declare bindings ====================
rabbitmqadmin -N apollo --vhost=fincloud declare binding source="fincloud.exchange.loan" destination="fincloud.queue.loanConfirmation" routing_key="fincloud.routingKey.loanConfirmation"
rabbitmqadmin -N apollo --vhost=fincloud declare binding source="fincloud.exchange.loan" destination="fincloud.queue.buyBackLoan" routing_key="fincloud.routingKey.buyBackLoan"
rabbitmqadmin -N apollo --vhost=fincloud declare binding source="fincloud.exchange.loan" destination="fincloud.queue.cashPaymentLoan" routing_key="fincloud.routingKey.cashPaymentLoan"
rabbitmqadmin -N apollo --vhost=fincloud declare binding source="fincloud.exchange.order" destination="fincloud.queue.orderStatus" routing_key="fincloud.routingKey.orderStatus"

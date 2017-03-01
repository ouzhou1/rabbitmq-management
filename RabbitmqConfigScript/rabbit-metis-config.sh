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
rabbitmqadmin declare user name=metis password=metis tags=management

#==================== declare virtual hosts ====================
rabbitmqadmin declare vhost name=fincloud

#==================== declare permissions ====================
# permission for metis to send message to fincloud.exchange.loan
rabbitmqadmin declare permission vhost=fincloud user=metis configure="^fincloud\.exchange\.(loan|notification|oplog)|fincloud\.queue\.(notification\.(sms|email))|(oplog|cashPaymentLoan|buyBackLoan)$" write="^fincloud\.exchange\.(loan|notification|oplog)|fincloud\.queue\.(notification\.(sms|email))|(oplog|cashPaymentLoan|buyBackLoan)$" read="^fincloud\.exchange\.(loan|notification|oplog)|fincloud\.queue\.(notification\.(sms|email))|(oplog|cashPaymentLoan|buyBackLoan)$"

#==================== declare exchanges ====================
# exchange for sms
rabbitmqadmin -N metis --vhost=fincloud declare exchange name="fincloud.exchange.notification" type=topic durable=true
# exchange for loan
rabbitmqadmin -N metis --vhost=fincloud declare exchange name="fincloud.exchange.loan" type=topic durable=true

#==================== declare queues ====================
# queues for loan
rabbitmqadmin -N metis --vhost=fincloud declare queue name="fincloud.queue.cashPaymentLoan" durable=true
rabbitmqadmin -N metis --vhost=fincloud declare queue name="fincloud.queue.buyBackLoan" durable=true
# queue for sending sms
rabbitmqadmin -N metis --vhost=fincloud declare queue name="fincloud.queue.notification.sms" durable=true
# queue for sending email
rabbitmqadmin -N metis --vhost=fincloud declare queue name="fincloud.queue.notification.email" durable=true

#==================== declare bindings ====================
rabbitmqadmin -N metis --vhost=fincloud declare binding source="fincloud.exchange.notification" destination="fincloud.queue.notification.sms" routing_key=fincloud.routingKey.sms
rabbitmqadmin -N metis --vhost=fincloud declare binding source="fincloud.exchange.notification" destination="fincloud.queue.notification.email" routing_key=fincloud.routingKey.email
rabbitmqadmin -N metis --vhost=fincloud declare binding source="fincloud.exchange.loan" destination="fincloud.queue.cashPaymentLoan" routing_key=fincloud.routingKey.payLoan
rabbitmqadmin -N metis --vhost=fincloud declare binding source="fincloud.exchange.loan" destination="fincloud.queue.buyBackLoan" routing_key=fincloud.routingKey.buybackLoan

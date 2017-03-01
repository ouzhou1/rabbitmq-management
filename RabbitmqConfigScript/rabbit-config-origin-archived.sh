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
rabbitmqadmin declare user name=rhea password=rheay tags=
rabbitmqadmin declare user name=janus_mobile password=janus_mobile tags=
rabbitmqadmin declare user name=janus_platform password=janus_platform tags=
rabbitmqadmin declare user name=metis password=metis tags=
rabbitmqadmin declare user name=toms password=toms tags=
rabbitmqadmin declare user name=demeter password=demeter tags=
rabbitmqadmin declare user name=apollo password=apollo tags=

#==================== declare virtual hosts ====================
rabbitmqadmin declare vhost name=fincloud
rabbitmqadmin declare permission vhost=fincloud user=admin configure=.* write=.* read=.*

#==================== declare exchanges ====================
# exchange for sms
rabbitmqadmin --vhost=fincloud declare exchange name=fincloud.exchange.notification type=topic durable=true

# exchange for alert 
rabbitmqadmin --vhost=fincloud declare exchange name=fincloud.exchange.alert type=topic durable=true

# exchange for loan
rabbitmqadmin --vhost=fincloud declare exchange name=fincloud.exchange.loan type=topic durable=true

# exchange for order
rabbitmqadmin --vhost=fincloud declare exchange name=fincloud.exchange.order type=topic durable=true

# exchange for operation logs
rabbitmqadmin --vhost=fincloud declare exchange name=fincloud.exchange.oplog type=topic durable=true

#==================== declare queues ====================
# queue for sending sms
rabbitmqadmin --vhost=fincloud declare queue name=fincloud.queue.notification.sms durable=true

# queue for sending email
rabbitmqadmin --vhost=fincloud declare queue name=fincloud.queue.notification.email durable=true

# queue for alert
rabbitmqadmin --vhost=fincloud declare queue name=fincloud.queue.alert durable=true

# queue for operation logs
rabbitmqadmin --vhost=fincloud declare queue name=fincloud.queue.oplog durable=true

# queues for loan
rabbitmqadmin --vhost=fincloud declare queue name=fincloud.queue.loanConfirmation durable=true
rabbitmqadmin --vhost=fincloud declare queue name=fincloud.queue.buybackLoan durable=true
rabbitmqadmin --vhost=fincloud declare queue name=fincloud.queue.cashPayment durable=true

# queue for order
rabbitmqadmin --vhost=fincloud declare queue name=fincloud.queue.orderStatus durable=true

#==================== declare bindings ====================
rabbitmqadmin --vhost=fincloud declare binding source=fincloud.exchange.notification destination=fincloud.queue.notification.sms routing_key=fincloud.routingKey.sms
rabbitmqadmin --vhost=fincloud declare binding source=fincloud.exchange.notification destination=fincloud.queue.notification.email routing_key=fincloud.routingKey.email

rabbitmqadmin --vhost=fincloud declare binding source=fincloud.exchange.alert destination=fincloud.queue.alert routing_key=fincloud.routingKey.alert

rabbitmqadmin --vhost=fincloud declare binding source=fincloud.exchange.oplog destination=fincloud.queue.oplog routing_key=fincloud.routingKey.oplog

rabbitmqadmin --vhost=fincloud declare binding source=fincloud.exchange.loan destination=fincloud.queue.loanConfirmation routing_key=fincloud.routingKey.loanConfirmation
rabbitmqadmin --vhost=fincloud declare binding source=fincloud.exchange.loan destination=fincloud.queue.buyBackLoan routing_key=fincloud.routingKey.buyBackLoan
rabbitmqadmin --vhost=fincloud declare binding source=fincloud.exchange.loan destination=fincloud.queue.cashPaymentLoan routing_key=fincloud.routingKey.cashPaymentLoan

rabbitmqadmin --vhost=fincloud declare binding source=fincloud.exchange.order destination=fincloud.queue.orderStatus routing_key=fincloud.routingKey.orderStatus

# declare permissions
rabbitmqadmin declare permission vhost=fincloud user=rhea configure= write= read=fincloud.queue.notification.sms
rabbitmqadmin declare permission vhost=fincloud user=rhea configure= write= read=fincloud.queue.notification.email

rabbitmqadmin declare permission vhost=fincloud user=janus_mobile configure= write=fincloud.exchange.notification read=
rabbitmqadmin declare permission vhost=fincloud user=janus_platform configure= write= read=fincloud.queue.orderStatus

rabbitmqadmin declare permission vhost=fincloud user=metis configure= write=fincloud.exchange.loan read=
rabbitmqadmin declare permission vhost=fincloud user=metis configure= write=fincloud.exchange.notification read=

rabbitmqadmin declare permission vhost=fincloud user=toms configure= write=fincloud.exchange.oplog read=

rabbitmqadmin declare permission vhost=fincloud user=demeter configure= write=fincloud.exchange.notification read=
rabbitmqadmin declare permission vhost=fincloud user=demeter configure= write=fincloud.exchange.oplog read=

rabbitmqadmin declare permission vhost=fincloud user=apollo configure= write= read=fincloud.queue.loanConfirmation
rabbitmqadmin declare permission vhost=fincloud user=apollo configure= write= read=fincloud.queue.buyBackLoan
rabbitmqadmin declare permission vhost=fincloud user=apollo configure= write= read=fincloud.queue.cashPaymentLoan
rabbitmqadmin declare permission vhost=fincloud user=apollo configure= write=fincloud.exchange.order read=
rabbitmqadmin declare permission vhost=fincloud user=apollo configure= write= read=fincloud.queue.cashPaymentLoan

rabbitmqadmin export test.config
rabbitmqadmin import test.config

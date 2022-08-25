import pika
import sys
import os
import time
from scripts.send_mail import send_mail
from scripts.util import search_talent_log

def main():
    connection = pika.BlockingConnection(pika.ConnectionParameters(host='localhost'))
    channel = connection.channel()

    channel.queue_declare(queue='student_mail_sending')
    channel.queue_declare(queue='employee_mail_sending')
    channel.queue_declare(queue='logging')
    channel.queue_declare(queue='search_logging')

    def callback_std_mail(ch, method, properties, body):
        print(" [x] Received %r" % body)
        mail = eval(body.decode())
        
        email = mail['email']
        subject = mail['subject']
        body = mail['body']

        send_mail(email, subject, body)
        time.sleep(1)

    def callback_emp_mail(ch, method, properties, body):
        print(" [x] Received %r" % body)
        mail = eval(body.decode())
        
        email = mail['email']
        subject = mail['subject']
        body = mail['body']

        send_mail(email, subject, body)
        time.sleep(1)

    def callback_log(ch, method, properties, body):
        print(" [x] Received %r" % body)
        k=body.decode()
        print(k)
        time.sleep(1)

    def callback_search_log(ch, method, properties, body):
        print(" [x] Received %r" % body)
        info = eval(body.decode())

        selected_filter = info['selected_filter']
        filtered_by = info['filtered_by']

        search_talent_log(selected_filter, filtered_by)
        time.sleep(1)

    channel.basic_consume(queue='student_mail_sending', on_message_callback=callback_std_mail, auto_ack=True)
    channel.basic_consume(queue='employee_mail_sending', on_message_callback=callback_emp_mail, auto_ack=True)
    channel.basic_consume(queue='logging', on_message_callback=callback_log, auto_ack=True)
    channel.basic_consume(queue='search_logging', on_message_callback=callback_search_log, auto_ack=True)

    channel.start_consuming()

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('Interrupted')
        try:
            sys.exit(0)
        except SystemExit:
            os._exit(0)
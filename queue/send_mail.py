import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

def send_mail(mail, subject, body):
    try:
        username = "platform@upschool.io"
        password = "Alperen123"
        mail_from = "platform@upschool.io"
        mail_to = mail
        mail_subject = subject
        mail_body = body

        mimemsg = MIMEMultipart()
        mimemsg["From"] = mail_from
        mimemsg["To"] = mail_to
        mimemsg["Subject"] = mail_subject
        mimemsg.attach(MIMEText(mail_body,"plain"))
        connection = smtplib.SMTP(host="smtp.office365.com", port=587)
        connection.starttls()
        connection.login(username,password)
        connection.send_message(mimemsg)
        connection.quit()
        return True
    except Exception as e:
        print(e)
        return False
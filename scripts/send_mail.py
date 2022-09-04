import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

html = """\
        <html>
        <head></head>
        <body>
            <p>Hi!<br>
            How are you?<br>
            Here is the <a href="http://example2.com">link</a> you wanted.
            <img src="http://example2.com/static/hello.jpg"/>
            </p>
        </body>
        </html>
        """

def send_mail(mail, subject, body):
    try:
        username = "platform@upschool.io"
        password = "Alperen123"
        mail_from = "platform@upschool.io"
        mail_to = mail
        mail_subject = subject
        mail_body = body

        html = """\
        <html>
        <head></head>
        <body>
            <p>Hi!<br>
            How are you?<br>
            Here is the <a href="http://example2.com">link</a> you wanted.
            <img src="http://example2.com/static/hello.jpg"/>
            </p>
        </body>
        </html>
        """

        mimemsg = MIMEMultipart()
        mimemsg["From"] = mail_from
        mimemsg["To"] = mail_to
        mimemsg["Subject"] = mail_subject
        mimemsg.attach(MIMEText(html,"html"))
        connection = smtplib.SMTP(host="smtp.office365.com", port=587)
        connection.starttls()
        connection.login(username,password)
        connection.send_message(mimemsg)
        connection.quit()
        return True
    except Exception as e:
        print(e)
        return False
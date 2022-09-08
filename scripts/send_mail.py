import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from util import app

def generate_email_template(text, link):
    html = f"""\
    <html>\
    <head>\
    <style>\
    * {{\
    margin: 0;\
    font-family: Arial, Helvetica, sans-serif;\
    }}\
    .container {{\
    display: grid;\
    grid-template-columns: 1fr 1fr 1fr;\
    background-color: #332C49;\
    height: 100vh;\
    }}\
    .content {{\
    padding: 3rem;\
    background-color: #332C49;\
    box-shadow: 0 3px 3px 3px #212121;
    }}\
    .logo {{\
    padding: 0;\
    margin: 2rem auto;\
    max-width: 219px;\
    }}\
    .box {{\
    margin: 0 auto;\
    padding: 1rem;\
    background-color: #f2f2f2;\
    border-style: solid;\
    border-color: #e2e2e2;\
    border-radius: 15px;\
    box-shadow: 0 5px 1rem #212121;\
    max-width: 24rem;\
    }}\
    </style>\
    </head>\
    <body>\
    <div class="container">\
    <div class="empty-column"></div>\
    <section class="content">\
    <div class="box">\
    <div class="logo">\
    <img src="https://lh3.googleusercontent.com/drive-viewer/AJc5JmQpHjdHea7XnbT8AVgsovS6X4srrzpLcpURorFz6z7sPp3Fo8HvuUDF91_Yi2eHMUMch9qm60A=w1857-h981" alt="logo" width="219" height="59">\
    </div>\
    <p style="display: inline;">{text}</p>\
    <a style="margin: 0 0 1rem 0;word-break: break-all;" href="{link}">{link}</a>\
    </div>\
    </section>\
    <div class="empty-column"></div>\
    </div>\
    </body>\
    </html>"""
    
    return html

def send_mail(mail, subject, body):
    try:
        username = app.config['MAIL_SENDER']
        password = app.config['MAIL_SENDER_PASSWORD']
        mail_from = app.config['MAIL_SENDER']
        mail_to = mail
        mail_subject = subject
        mail_body = body

        mimemsg = MIMEMultipart()
        mimemsg["From"] = mail_from
        mimemsg["To"] = mail_to
        mimemsg["Subject"] = mail_subject
        mimemsg.attach(MIMEText(mail_body,"html"))
        connection = smtplib.SMTP(host=app.config['SMTP_SERVER'], port=app.config['SMTP_PORT'])
        connection.starttls()
        connection.login(username,password)
        connection.send_message(mimemsg)
        connection.quit()
        return True
    except Exception as e:
        print(e)
        return False
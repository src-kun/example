# !/usr/bin/python
# -*- coding: UTF-8 -*-

import smtplib
from email.mime.text import MIMEText
from email.header import Header

mail_host = "smtp.exmail.qq.com"
mail_user = "test@domain.com"
mail_pass = "password"

sender = 'test@domain.com'
receiver = 'a@domain.com'
subject = 'subject'
body = u"""
test
"""

message = MIMEText(body, 'plain', 'utf-8')
message['From'] = Header(sender, 'utf-8')
message['To'] = Header(receiver, 'utf-8')
message['Subject'] = Header(subject, 'utf-8')

try:
    smtp = smtplib.SMTP_SSL(mail_host, 465)
    smtp.ehlo()
    smtp.login(mail_user, mail_pass)

    # 发送邮件
    smtp.sendmail(sender, receiver, message.as_string())
    smtp.close()
    print('ok.')
except smtplib.SMTPException as e:
    print(e)
    print("Error: 无法发送邮件")

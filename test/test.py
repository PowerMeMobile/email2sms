# -*- coding: utf-8 -*-

import pytest
import os

EMAIL_HOST = os.getenv('EMAIL_HOST')
if EMAIL_HOST == None or EMAIL_HOST == '':
    EMAIL_HOST = '127.0.0.1'

EMAIL_PORT = os.getenv('EMAIL_PORT')
if EMAIL_PORT == None or EMAIL_PORT == '':
    EMAIL_PORT = '2525'

FROM = 'whoever@mail.com'
TO = ['375296543210@mail.com', '375296543211@mail.com']
SUBJECT = '10009:user:password'

@pytest.fixture
def smtp():
    import smtplib
    smtp = smtplib.SMTP(EMAIL_HOST, EMAIL_PORT)
    resp, _msg = smtp.ehlo()
    assert resp == 250
    return smtp

# raw text
def test_raw_text_us_ascii(smtp):
    msg = """\
From: %s
To: %s
Subject: %s

%s
""" % (FROM, ",".join(TO), SUBJECT, 'raw text us-ascii')

    res = smtp.sendmail(FROM, TO, msg)
    assert {} == res

# text/plain
def test_text_plain_us_ascii(smtp):
    from email.mime.text import MIMEText

    msg = MIMEText('text/plain us-ascii')
    msg['From'] = FROM
    msg['To'] = ','.join(TO)
    msg['Subject'] = SUBJECT

    res = smtp.sendmail(msg['From'], msg['To'], msg.as_string())
    assert {} == res

# text/plain utf-8
def test_text_plain_utf_8(smtp):
    from email.mime.text import MIMEText

    msg = MIMEText('Привет, как дела?', _charset='utf-8')
    msg['From'] = FROM
    msg['To'] = ','.join(TO)
    msg['Subject'] = SUBJECT

    res = smtp.sendmail(msg['From'], msg['To'], msg.as_string())
    assert {} == res

# text/html
def test_text_html(smtp):
    from email.mime.text import MIMEText

    html = """\
<html>
  <head></head>
  <body>
    <p>text %2F html</p>
  </body>
</html>
"""

    msg = MIMEText(html, 'html')
    msg['From'] = FROM
    msg['To'] = ','.join(TO)
    msg['Subject'] = SUBJECT

    res = smtp.sendmail(msg['From'], msg['To'], msg.as_string())
    assert {} == res

# multipart/alternative
def test_multipart_alternative(smtp):
    from email.mime.multipart import MIMEMultipart
    from email.mime.text import MIMEText

    msg = MIMEMultipart('alternative')
    msg['From'] = FROM
    msg['To'] = ','.join(TO)
    msg['Subject'] = SUBJECT

    text = "text/alternative text"
    html = """\
<html>
  <head></head>
  <body>
    <p>text/alternative html</p>
  </body>
</html>
"""

    part1 = MIMEText(text, 'plain')
    part2 = MIMEText(html, 'html')

    msg.attach(part1)
    msg.attach(part2)

    res = smtp.sendmail(msg['From'], msg['To'], msg.as_string())
    assert {} == res

# multipart/mixed
def test_multipart_mixed(smtp):
    from email.mime.multipart import MIMEMultipart
    from email.mime.text import MIMEText

    msg = MIMEMultipart()
    msg['From'] = FROM
    msg['To'] = ','.join(TO)
    msg['Subject'] = SUBJECT
    msg.attach(MIMEText('multipart / mixed'))

    res = smtp.sendmail(msg['From'], msg['To'], msg.as_string())
    assert {} == res

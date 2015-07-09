# -*- coding: utf-8 -*-

import pytest
import os

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

EMAIL_HOST = os.getenv('EMAIL_HOST')
if EMAIL_HOST == None or EMAIL_HOST == '':
    EMAIL_HOST = '127.0.0.1'

EMAIL_PORT = os.getenv('EMAIL_PORT')
if EMAIL_PORT == None or EMAIL_PORT == '':
    EMAIL_PORT = '2525'

AUTH_FROM_ADDR = 'email-postpaid@mail.com'
AUTH_FROM_ADDR_BAD = 'whoever@mail.com'

AUTH_SUBJECT = '10009:user:password'
AUTH_SUBJECT_BAD = 'bad auth subject'

AUTH_TO_ADDR = '375296660009@mail.com'
AUTH_TO_ADDR_BAD = 'bad_number@mail.com'

TO = '375296543210@mail.com'
TO2 = ['375296543210@mail.com', '375296543211@mail.com']


@pytest.fixture
def smtp():
    smtp = smtplib.SMTP(EMAIL_HOST, EMAIL_PORT)
    resp, _msg = smtp.ehlo()
    assert resp == 250
    return smtp

#
# Utils
#

def sendmail(smtp, f, t, msg):
    try:
        return smtp.sendmail(f, t, msg)
    except smtplib.SMTPDataError as (code, resp):
        return (code, resp)

#
# Auth schemes
#

def test_auth_from_address_succ(smtp):
    msg = MIMEText('from_address test')
    msg['From'] = AUTH_FROM_ADDR
    msg['To'] = TO
    res = sendmail(smtp, msg['From'], msg['To'], msg.as_string())
    assert {} == res

def test_auth_from_address_fail(smtp):
    msg = MIMEText('from_address test')
    msg['From'] = AUTH_FROM_ADDR_BAD
    msg['To'] = TO
    (code, resp) = sendmail(smtp, msg['From'], msg['To'], msg.as_string())
    assert code == 550
    assert resp == 'Invalid user account'

def test_auth_subject_succ(smtp):
    msg = MIMEText('subject test')
    msg['From'] = AUTH_FROM_ADDR_BAD
    msg['To'] = TO
    msg['Subject'] = AUTH_SUBJECT
    res = sendmail(smtp, msg['From'], msg['To'], msg.as_string())
    assert {} == res

def test_auth_subject_fail(smtp):
    msg = MIMEText('subject test')
    msg['From'] = AUTH_FROM_ADDR_BAD
    msg['To'] = TO
    msg['Subject'] = AUTH_SUBJECT_BAD
    (code, resp) = sendmail(smtp, msg['From'], msg['To'], msg.as_string())
    assert code == 550
    assert resp == 'Invalid user account'

def test_auth_to_address_succ(smtp):
    msg = MIMEText('to_address test')
    msg['From'] = AUTH_FROM_ADDR_BAD
    msg['To'] = AUTH_TO_ADDR
    res = sendmail(smtp, msg['From'], msg['To'], msg.as_string())
    assert {} == res

def test_auth_to_address_fail(smtp):
    msg = MIMEText('to_address test')
    msg['From'] = AUTH_FROM_ADDR_BAD
    msg['To'] = AUTH_TO_ADDR_BAD
    (code, resp) = sendmail(smtp, msg['From'], msg['To'], msg.as_string())
    assert code == 550
    assert resp == 'Invalid user account'

#
# MIME content types
#

# raw text
def test_raw_text_us_ascii(smtp):
    msg = """\
From: %s
To: %s
Subject: %s

%s
""" % (AUTH_FROM_ADDR_BAD, TO, AUTH_SUBJECT, 'raw text us-ascii')
    res = sendmail(smtp, AUTH_FROM_ADDR_BAD, TO, msg)
    assert {} == res

def test_text_plain_us_ascii(smtp):
    msg = MIMEText('text plain us-ascii')
    msg['From'] = AUTH_FROM_ADDR_BAD
    msg['To'] = TO
    msg['Subject'] = AUTH_SUBJECT
    res = sendmail(smtp, msg['From'], msg['To'], msg.as_string())
    assert {} == res

def test_text_plain_utf_8(smtp):
    msg = MIMEText('Привет, как дела?', _charset='utf-8')
    msg['From'] = AUTH_FROM_ADDR_BAD
    msg['To'] = TO
    msg['Subject'] = AUTH_SUBJECT
    res = sendmail(smtp, msg['From'], msg['To'], msg.as_string())
    assert {} == res

def test_text_html(smtp):
    html = """\
<html>
  <head></head>
  <body>
    <p>text %2F html</p>
  </body>
</html>
"""
    msg = MIMEText(html, 'html')
    msg['From'] = AUTH_FROM_ADDR_BAD
    msg['To'] = TO
    msg['Subject'] = AUTH_SUBJECT
    res = sendmail(smtp, msg['From'], msg['To'], msg.as_string())
    assert {} == res

def test_multipart_alternative(smtp):
    msg = MIMEMultipart('multipart alternative')
    msg['From'] = AUTH_FROM_ADDR_BAD
    msg['To'] = TO
    msg['Subject'] = AUTH_SUBJECT
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
    res = sendmail(smtp, msg['From'], msg['To'], msg.as_string())
    assert {} == res

def test_multipart_mixed(smtp):
    msg = MIMEMultipart()
    msg['From'] = AUTH_FROM_ADDR_BAD
    msg['To'] = TO
    msg['Subject'] = AUTH_SUBJECT
    msg.attach(MIMEText('multipart mixed'))
    res = sendmail(smtp, msg['From'], msg['To'], msg.as_string())
    assert {} == res

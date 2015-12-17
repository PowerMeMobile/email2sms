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


# curl -s -D - -X POST 127.0.0.1:8080/v1/customers -d "customer_uuid=4c070aa2-3a54-4ed2-9a12-6f6dcdbbd807&customer_id=10011&name=email-postpaid-blacklist-bypass-enabled&priority=1&rps=1000&network_map_id=c51a94bf-618a-48a4-90bf-7508e3d93b5d&receipts_allowed=true&no_retry=false&default_validity=000003000000000R&max_validity=259200&default_provider_id=&interfaces=email&features=inbox,true;bypass_blacklist,true&pay_type=postpaid&credit=10000.0&credit_limit=10000.0&language=en&state=active"

# curl -s -D - -X POST 127.0.0.1:8080/v1/customers/4c070aa2-3a54-4ed2-9a12-6f6dcdbbd807/originators -d "id=17d225de-82a9-4907-837d-22276d43e82c&msisdn=FromEmail,5,0&description=&is_default=true&routings=&state=approved"

# curl -s -D - -X POST 127.0.0.1:8080/v1/customers/4c070aa2-3a54-4ed2-9a12-6f6dcdbbd807/users -d "user_id=user&password=password&interfaces=email&features=inbox,true;sms_from_email,true&mobile_phone=375296660011&first_name=&last_name=&company=&occupation=&email=email-postpaid-bypass-blacklist-enabled@mail.com&country=&language=en&state=active"

AUTH_FROM_ADDR = 'email-postpaid@mail.com'
AUTH_FROM_ADDR_BAD = 'd.klionsky@dev1team.net'
AUTH_FROM_ADDR_USER_NO_EMAIL_IF = 'email_no_email_if-postpaid@mail.com'
AUTH_FROM_ADDR_BYPASS_BLACKLIST = 'email-postpaid-bypass-blacklist-enabled@mail.com'

AUTH_SUBJECT = '10009:user:password'
AUTH_SUBJECT_BAD = 'bad auth subject'
AUTH_SUBJECT_BAD_PASSWORD = '10009:user:bad_password'

AUTH_TO_ADDR = '375296660009@mail.com'
AUTH_TO_ADDR_NOT_ALLOWED = '375296660019@mail.com'
AUTH_TO_ADDR_BAD = '375296669999@mail.com'

TO = '375296543210@mail.com'

TO2 = ['375296543210@mail.com', '375296543211@mail.com']
TO3 = ['375296543210@mail.com', '375296543211@mail.com', '375296543212@mail.com']
TO4 = ['375296543210@mail.com', '375296543211@mail.com', '375296543212@mail.com', '375296543212@mail.com']
TO2_BAD_DOMAINS = ['375296543210@mail2.com', '375296543211@mail2.com']
TO2_BAD_COVERAGE = ['888296543210@mail.com', '888296543211@mail.com']
TO_NOT_MSISDN = 'alphanumeric@mail.com'
TO_BLACKLISTED_MSISDN = '375296666666@mail.com'

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
    res = sendmail(smtp, msg['From'], TO, msg.as_string())
    assert {} == res

def test_auth_from_address_fail(smtp):
    msg = MIMEText('from_address test')
    msg['From'] = AUTH_FROM_ADDR_BAD
    msg['To'] = TO
    (code, resp) = sendmail(smtp, msg['From'], TO, msg.as_string())
    assert code == 550
    assert resp == 'Invalid user account'

def test_auth_from_address_user_no_email_if_fail(smtp):
    msg = MIMEText('from_address test')
    msg['From'] = AUTH_FROM_ADDR_USER_NO_EMAIL_IF
    ## both subject and to_address auth are valid.
    ## the test should fail nonetheless because customer is found,
    ## but doesn't have email interface
    msg['To'] = AUTH_TO_ADDR
    msg['Subject'] = AUTH_SUBJECT
    (code, resp) = sendmail(smtp, msg['From'], TO, msg.as_string())
    assert code == 550
    assert resp == 'Invalid user account'

def test_auth_subject_succ(smtp):
    msg = MIMEText('subject test')
    msg['From'] = AUTH_FROM_ADDR_BAD
    msg['To'] = TO
    msg['Subject'] = AUTH_SUBJECT
    res = sendmail(smtp, msg['From'], TO, msg.as_string())
    assert {} == res

def test_auth_subject_bad_subject_fail(smtp):
    msg = MIMEText('subject test')
    msg['From'] = AUTH_FROM_ADDR_BAD
    msg['To'] = TO
    msg['Subject'] = AUTH_SUBJECT_BAD
    (code, resp) = sendmail(smtp, msg['From'], TO, msg.as_string())
    assert code == 550
    assert resp == 'Invalid user account'

def test_auth_subject_bad_password_fail(smtp):
    ## to_address auth is valid.
    ## the test should fail nonetheless because customer is found,
    ## but the password is wrong
    msg = MIMEText('subject test')
    msg['From'] = AUTH_FROM_ADDR_BAD
    msg['To'] = AUTH_TO_ADDR
    msg['Subject'] = AUTH_SUBJECT_BAD_PASSWORD
    (code, resp) = sendmail(smtp, msg['From'], TO, msg.as_string())
    assert code == 550
    assert resp == 'Invalid user account'

def test_auth_to_address_succ(smtp):
    msg = MIMEText('to_address test')
    msg['From'] = AUTH_FROM_ADDR_BAD
    msg['To'] = AUTH_TO_ADDR
    res = sendmail(smtp, msg['From'], AUTH_TO_ADDR, msg.as_string())
    assert {} == res

def test_auth_to_address_fail(smtp):
    msg = MIMEText('to_address test')
    msg['From'] = AUTH_FROM_ADDR_BAD
    msg['To'] = AUTH_TO_ADDR_BAD
    (code, resp) = sendmail(smtp, msg['From'], AUTH_TO_ADDR_BAD, msg.as_string())
    assert code == 550
    assert resp == 'Invalid user account'

def test_auth_to_address_no_allowed_fail(smtp):
    msg = MIMEText('to_address test')
    msg['From'] = AUTH_FROM_ADDR_BAD
    msg['To'] = AUTH_TO_ADDR_NOT_ALLOWED
    (code, resp) = sendmail(smtp, msg['From'], AUTH_TO_ADDR_NOT_ALLOWED, msg.as_string())
    assert code == 550
    assert resp == 'Invalid user account'


def test_send_to_non_msisdn_fail(smtp):
    msg = MIMEText('send to non msisdn should fail')
    msg['From'] = AUTH_FROM_ADDR
    msg['To'] = TO_NOT_MSISDN
    (code, resp) = sendmail(smtp, msg['From'], TO_NOT_MSISDN, msg.as_string())
    assert code == 550
    assert resp == 'No valid recipients found'

def test_send_blacklisted_msisdn_fail(smtp):
    msg = MIMEText('send to blacklisted msisdn should fail')
    msg['From'] = AUTH_FROM_ADDR
    msg['To'] = TO_BLACKLISTED_MSISDN
    (code, resp) = sendmail(smtp, msg['From'], TO_BLACKLISTED_MSISDN, msg.as_string())
    assert code == 550
    assert resp == 'No valid recipients found'

def test_bypass_blacklist_succ(smtp):
    msg = MIMEText('bypass blacklist should succ')
    msg['From'] = AUTH_FROM_ADDR_BYPASS_BLACKLIST
    msg['To'] = TO_BLACKLISTED_MSISDN
    res = sendmail(smtp, msg['From'], TO_BLACKLISTED_MSISDN, msg.as_string())
    assert {} == res

#
# MIME content types
#

# raw text
def test_raw_text_us_ascii_succ(smtp):
    msg = """\
From: %s
To: %s
Subject: %s

%s
""" % (AUTH_FROM_ADDR_BAD, TO, AUTH_SUBJECT, 'raw text us-ascii')
    res = sendmail(smtp, AUTH_FROM_ADDR_BAD, TO, msg)
    assert {} == res

def test_text_plain_us_ascii_succ(smtp):
    msg = MIMEText('text plain us-ascii')
    msg['From'] = AUTH_FROM_ADDR_BAD
    msg['To'] = TO
    msg['Subject'] = AUTH_SUBJECT
    res = sendmail(smtp, msg['From'], TO, msg.as_string())
    assert {} == res

def test_text_plain_utf_8_succ(smtp):
    msg = MIMEText('Привет, как дела?', _charset='utf-8')
    msg['From'] = AUTH_FROM_ADDR_BAD
    msg['To'] = TO
    msg['Subject'] = AUTH_SUBJECT
    res = sendmail(smtp, msg['From'], TO, msg.as_string())
    assert {} == res

def test_text_html_succ(smtp):
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
    res = sendmail(smtp, msg['From'], TO, msg.as_string())
    assert {} == res

def test_multipart_alternative_succ(smtp):
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
    res = sendmail(smtp, msg['From'], TO, msg.as_string())
    assert {} == res

def test_multipart_mixed_succ(smtp):
    msg = MIMEMultipart()
    msg['From'] = AUTH_FROM_ADDR_BAD
    msg['To'] = TO
    msg['Subject'] = AUTH_SUBJECT
    msg.attach(MIMEText('multipart mixed'))
    res = sendmail(smtp, msg['From'], TO, msg.as_string())
    assert {} == res

#
# Filter by domains
#

def test_filter_by_domains_2_ok_succ(smtp):
    msg = MIMEText('filter by domain test')
    msg['From'] = AUTH_FROM_ADDR_BAD
    msg['To'] = ','.join(TO2)
    msg['Subject'] = AUTH_SUBJECT
    res = sendmail(smtp, msg['From'], TO2, msg.as_string())
    assert {} == res

def test_filter_by_domains_2_bad_fail(smtp):
    msg = MIMEText('filter by domain test')
    msg['From'] = AUTH_FROM_ADDR_BAD
    msg['To'] = ','.join(TO2_BAD_DOMAINS)
    msg['Subject'] = AUTH_SUBJECT
    (code, resp) = sendmail(smtp, msg['From'], TO2_BAD_DOMAINS, msg.as_string())
    assert code == 550
    assert resp == 'No valid recipients found'

# assumes invalid_recipient_policy == reject_message
def test_filter_by_domains_2_ok_2_bad_fail(smtp):
    msg = MIMEText('filter by domain test')
    msg['From'] = AUTH_FROM_ADDR_BAD
    msg['To'] = ','.join(TO2 + TO2_BAD_DOMAINS)
    msg['Subject'] = AUTH_SUBJECT
    (code, resp) = sendmail(smtp, msg['From'], TO2 + TO2_BAD_DOMAINS, msg.as_string())
    assert code == 550
    assert resp == 'Rejected by invalid recipient policy'

#
# Filter by coverage
#

def test_filter_by_coverage_3_ok_succ(smtp):
    msg = MIMEText('filter by coverage test')
    msg['From'] = AUTH_FROM_ADDR_BAD
    msg['To'] = ','.join(TO3)
    msg['Subject'] = AUTH_SUBJECT
    res = sendmail(smtp, msg['From'], TO3, msg.as_string())
    assert {} == res

# assumes smtp_max_recipient_count == 3
def test_filter_by_coverage_4_ok_fail(smtp):
    msg = MIMEText('filter by coverage test')
    msg['From'] = AUTH_FROM_ADDR_BAD
    msg['To'] = ','.join(TO4)
    msg['Subject'] = AUTH_SUBJECT
    (code, resp) = sendmail(smtp, msg['From'], TO4, msg.as_string())
    assert code == 550
    assert resp == 'Too many recipients specified'

def test_filter_by_coverage_2_bad_fail(smtp):
    msg = MIMEText('filter by coverage test')
    msg['From'] = AUTH_FROM_ADDR_BAD
    msg['To'] = ','.join(TO2_BAD_COVERAGE)
    msg['Subject'] = AUTH_SUBJECT
    (code, resp) = sendmail(smtp, msg['From'], TO2_BAD_COVERAGE, msg.as_string())
    assert code == 550
    assert resp == 'No valid recipients found'

# assumes invalid_recipient_policy == reject_message
def test_filter_by_coverage_2_ok_2_bad_fail(smtp):
    msg = MIMEText('filter by coverage test')
    msg['From'] = AUTH_FROM_ADDR_BAD
    msg['To'] = ','.join(TO2 + TO2_BAD_COVERAGE)
    msg['Subject'] = AUTH_SUBJECT
    (code, resp) = sendmail(smtp, msg['From'], TO2 + TO2_BAD_COVERAGE, msg.as_string())
    assert code == 550
    assert resp == 'Rejected by invalid recipient policy'

#
# Message content
#

# assumes max_msg_parts == 10
def test_10_msg_parts_succ(smtp):
    msg = MIMEText('Very Long Message ' * 85)
    msg['From'] = AUTH_FROM_ADDR_BAD
    msg['To'] = TO
    msg['Subject'] = AUTH_SUBJECT
    res = sendmail(smtp, msg['From'], TO, msg.as_string())
    assert {} == res

# assumes max_msg_parts == 10
def test_11_msg_parts_fail(smtp):
    msg = MIMEText('Very Long Message ' * 86)
    msg['From'] = AUTH_FROM_ADDR_BAD
    msg['To'] = TO
    msg['Subject'] = AUTH_SUBJECT
    (code, resp) = sendmail(smtp, msg['From'], TO, msg.as_string())
    assert code == 550
    assert resp == 'Too many SMS parts'

#
# Internal error
#

def test_internal_error_succ(smtp):
    msg = MIMEText('internal error test')
    msg['From'] = AUTH_FROM_ADDR_BAD
    msg['To'] = '; '.join(TO2)
    msg['Subject'] = AUTH_SUBJECT
    (code, resp) = sendmail(smtp, msg['From'], TO2, msg.as_string())
    assert code == 554
    assert resp == 'Internal server error'

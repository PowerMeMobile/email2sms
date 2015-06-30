import pytest

@pytest.fixture
def smtp():
    import smtplib
    return smtplib.SMTP('127.0.0.1', 2525)

def test_ehlo(smtp):
    response, _msg = smtp.ehlo()
    assert response == 250

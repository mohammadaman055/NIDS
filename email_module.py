from email.message import EmailMessage
import ssl
import smtplib

def send_email(result, attack,threads):
    email_sender = 'nidsystemPU@gmail.com'
    email_password = 'gnqkgzjwlzfbafqd'
    email_recipient = 'your_email@gmail.com'

    subject = 'Intruders Detected'
    body = f"""
    This is to notify you that there was an intrusion detected over your system IP:192.168.1.10.
    Result: {result}
    Attack: {attack}
    threads: {threads}
    Now, this is an ADMIN call to look over the issue.
    Regards,
    NIDSystem
    """

    em = EmailMessage()
    em['From'] = email_sender
    em['To'] = email_recipient
    em['Subject'] = subject
    em.set_content(body)

    context = ssl.create_default_context()

    with smtplib.SMTP_SSL('smtp.gmail.com', 465, context=context) as smtp:
        smtp.login(email_sender, email_password)
        smtp.sendmail(email_sender, email_recipient, em.as_string())
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from jinja2 import Environment, FileSystemLoader, select_autoescape

# Mailtrap (Email Testing) credentials
SMTP_SERVER = "sandbox.smtp.mailtrap.io"
SMTP_PORT = 2525
SMTP_USERNAME = "50ae6a9c0d5bc1"
SMTP_PASSWORD = "b31ea839cfb746"

# Jinja2 environment for email templates
env = Environment(
    loader=FileSystemLoader("phishing_backend/templates"),
    autoescape=select_autoescape(["html", "xml"]),
)

def send_email(to_email: str, base_url: str, token: str):
    template = env.get_template("phishing_email.html")

    html_content = template.render(
        base_url=base_url,
        token=token,
    )

    msg = MIMEMultipart("alternative")
    msg["Subject"] = "Important: Action Required"
    msg["From"] = "training@safework-demo.com"
    msg["To"] = to_email

    part = MIMEText(html_content, "html")
    msg.attach(part)

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.sendmail(msg["From"], [to_email], msg.as_string())
    except Exception as e:
        print("EMAIL ERROR:", e)
    raise

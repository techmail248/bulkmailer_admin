import time, ssl, smtplib, os, mimetypes
from email.message import EmailMessage
from jinja2 import Template
from models import db, EmailLog
from link_utils import prepare_tracked_html

def build_message(from_name, from_email, to_email, subject, html_body, attachment_path=None):
    msg = EmailMessage()
    from_hdr = f"{from_name} <{from_email}>" if from_name else from_email
    msg['From'] = from_hdr
    msg['To'] = to_email
    msg['Subject'] = subject
    msg.set_content('This email requires HTML support.')
    msg.add_alternative(html_body, subtype='html')
    if attachment_path and os.path.exists(attachment_path):
        ctype, encoding = mimetypes.guess_type(attachment_path)
        if ctype is None:
            ctype = 'application/octet-stream'
        maintype, subtype = ctype.split('/', 1)
        with open(attachment_path, 'rb') as f:
            msg.add_attachment(f.read(), maintype=maintype, subtype=subtype,
                               filename=os.path.basename(attachment_path))
    return msg

def send_bulk(app, user, campaign, recipients_rows, base_url, rate_per_minute=60):
    interval = max(0.0, 60.0 / max(1, rate_per_minute))
    sent = failed = 0

    subj_template = Template(campaign.subject)
    body_template = Template(campaign.html_body)

    context = ssl.create_default_context()

    with smtplib.SMTP(user.smtp_host, user.smtp_port) as server:
        server.starttls(context=context)
        server.login(user.smtp_user, app.decrypt(user.smtp_pass_enc))

        for i, row in enumerate(recipients_rows):
            email = str(row.get('email', '')).strip()
            if not email:
                continue
            token = os.urandom(16).hex()
            subject = subj_template.render(**row)
            body = body_template.render(**row)
            tracked_html = prepare_tracked_html(base_url, body, token)
            msg = build_message(user.from_name, user.from_email or user.smtp_user, email, subject, tracked_html, campaign.attachment_path)
            log = EmailLog(campaign_id=campaign.id, user_id=user.id, recipient=email, token=token)
            db.session.add(log)
            db.session.commit()
            try:
                server.send_message(msg)
                log.status = 'sent'
                sent += 1
            except Exception as e:
                log.status = 'failed'
                log.error = str(e)
                failed += 1
            finally:
                db.session.commit()
                if i < len(recipients_rows) - 1:
                    time.sleep(interval)
    return sent, failed

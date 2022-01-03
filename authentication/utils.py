from django.core.mail import EmailMessage

class Util:
    @classmethod
    def send_email(self, data):
        
        email = EmailMessage(
            subject=data['email_subject'], body=data['email_body'],to=data["to_email"])
        email.send()    
        
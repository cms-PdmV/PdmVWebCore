"""
Module that handles all email notifications
"""
import logging
import smtplib
from email.message import EmailMessage


class Emailer:
    """
    Emailer sends email notifications to users
    """

    def __init__(
        self,
        username: str,
        password: str,
        smtp_server: str = "smtp.cern.ch",
        smtp_port: int = 587,
    ):
        self.logger = logging.getLogger()
        self.username = username
        self.password = password
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port

    def __init_smtp_client(self):
        """
        Instantiates a SMTP client for sending email notifications
        """
        self.logger.info("Creating SMTP client")
        self.logger.info("SMTP server: %s", self.smtp_server)
        self.logger.info("SMTP port: %s", self.smtp_port)
        self.logger.info("Authenticating as username: %s", self.username)

        try:
            smtp_client = smtplib.SMTP(host=self.smtp_server, port=self.smtp_port)
            smtp_client.ehlo()
            smtp_client.starttls()
            smtp_client.ehlo()
            smtp_client.login(user=self.username, password=self.password)
            return smtp_client
        except OSError as error:
            self.logger.error("Error connecting to SMTP server: %s", error)
            raise error

    def get_recipients(self, obj):
        """
        Return list of emails of people that are in object's history
        """
        recipients = set()
        for entry in obj.get("history"):
            user = entry["user"]
            if not user or user == "automatic":
                continue

            recipients.add(f"{user}@cern.ch")

        self.logger.info(
            "Recipients of %s are %s", obj.get_prepid(), ", ".join(recipients)
        )

        return list(recipients)

    def send(self, subject, body, recipients):
        """
        Send email
        """
        # Create a text/plain message
        message = EmailMessage()
        body = body.strip()
        message.set_content(body)
        message["Subject"] = subject
        message["From"] = "PdmV Service Account <pdmvserv@cern.ch>"
        message["To"] = ", ".join(recipients)
        message["Cc"] = "pdmvserv@cern.ch"

        try:
            smtp = self.__init_smtp_client()
            self.logger.debug(
                "Sending email %s to %s", message["Subject"], message["To"]
            )
            smtp.send_message(message)
        except smtplib.SMTPException as error:
            self.logger.error("Error sending email: %s", error)
        finally:
            smtp.quit()

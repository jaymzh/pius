# vim:shiftwidth=2:tabstop=2:expandtab:textwidth=80:softtabstop=2:ai:
import getpass
import os
import smtplib
import socket

from email import message, quoprimime
from email.utils import formatdate

from six.moves import (
  email_mime_multipart, email_mime_text, email_mime_base,
)

from libpius.constants import (
  DEFAULT_MAIL_HOST, DEFAULT_MAIL_PORT, DEFAULT_MIME_EMAIL_TEXT,
  DEFAULT_NON_MIME_EMAIL_TEXT,
)
from libpius.exceptions import EncryptionKeyError, MailSendError
from libpius.util import clean_files, debug


class PiusMailer(object):
  def __init__(self, mail, display_name, host, port, user, tls, no_mime,
               override, msg_text, tmp_dir, local_mail_dir):
    self.mail = mail
    self.display_name = display_name
    self.host = host
    self.port = port
    self.user = user
    self.password = ''
    self.tls = tls
    self.no_pgp_mime = no_mime
    self.address_override = override
    self.message_text = msg_text
    self.tmp_dir = tmp_dir
    self.local_mail_dir = local_mail_dir

  @staticmethod
  def add_options(parser):
    parser.set_defaults(mail_host=DEFAULT_MAIL_HOST,
                        mail_port=DEFAULT_MAIL_PORT,
                        mail_tls=True)
    parser.add_option('-u', '--mail-user', dest='mail_user', metavar='USER',
                      type='not_another_opt', nargs=1,
                      help='Authenticate to the SMTP server, and use username'
                           ' USER. You will be prompted for the password.')
    parser.add_option('-S', '--no-mail-tls', action='store_false',
                      dest='mail_tls',
                      help='Do not use STARTTLS when talking to the SMTP'
                           ' server.')
    parser.add_option('-P', '--mail-port', dest='mail_port', metavar='PORT',
                      nargs=1, type='int',
                      help='Port of SMTP server. [default: %default]')
    parser.add_option('-O', '--no-pgp-mime', action='store_true',
                      dest='mail_no_pgp_mime',
                      help='Do not use PGP/Mime when sending email.')
    parser.add_option('-n', '--override-email', dest='mail_override',
                      metavar='EMAIL', nargs=1, type='email',
                      help='Rather than send to the user, send to this address.'
                           ' Mostly useful for debugging.')
    parser.add_option('-M', '--mail-text', dest='mail_text', metavar='FILE',
                      nargs=1, type='not_another_opt',
                      help='Use the text in FILE as the body of email when'
                           ' sending out emails instead of the default text.'
                           ' To see the default text use'
                           ' --print-default-email. Requires -m.')
    parser.add_option('-H', '--mail-host', dest='mail_host', metavar='HOSTNAME',
                      nargs=1, type='not_another_opt',
                      help='Hostname of SMTP server. [default: %default]')

  def pgp_mime(self):
    '''Accessor'''
    return not self.no_pgp_mime

  def get_pass(self):
    '''Prompt the user for their passphrase.'''
    self.password = getpass.getpass('Please enter your mail server password: ')

  def verify_pass(self):
    '''Verify the password we got works for SMTPAUTH.'''
    try:
      smtp = smtplib.SMTP(self.host, self.port)
    except socket.error as msg:
      raise MailSendError(msg)

    # NOTE WELL: SECURITY IMPORTANT NOTE!
    # In python 2.6 if you attempt to starttls() and the server doesn't
    # understand an exception is raised. However before that, it just carried on
    # and one could attempt to auth over a plain-text session. This is BAD!
    #
    # So, in order be secure on older pythons we ehlo() and then check the
    # response before attempting startls.
    try:
      smtp.ehlo()
      if not smtp.has_extn('STARTTLS'):
        # Emulate 2.6 behavior
        raise smtplib.SMTPException('Server does not support STARTTLS')
      smtp.starttls()
      # must ehlo after startls
      smtp.ehlo()
      smtp.login(self.user, self.password)
    except smtplib.SMTPAuthenticationError:
      return False
    except (smtplib.SMTPException, socket.error) as msg:
      raise MailSendError(msg)
    finally:
      smtp.quit()

    return True

  def _get_email_body(self, signer, keyid, email):
    '''Helper function to grab the right email body.'''
    interpolation_dict = {'keyid': keyid, 'signer': signer, 'email': email}
    if self.message_text:
      return open(self.message_text, 'r').read() % interpolation_dict
    else:
      if self.no_pgp_mime:
        return DEFAULT_NON_MIME_EMAIL_TEXT % interpolation_dict
      else:
        return DEFAULT_MIME_EMAIL_TEXT % interpolation_dict

  def _generate_pgp_mime_email(self, signer, email, keyid, filename, psigner):
    '''Generates the PGP/Mime body.

    The message headers MUST be added by the caller.'''

    msg = email_mime_multipart.MIMEMultipart(
        'encrypted', micalg="pgp-sha1", protocol="application/pgp-encrypted"
    )
    msg.preamble = 'This is an OpenPGP/MIME signed message (RFC 2440 and 3156)'

    # The signed part of the message. This is a MIME encapsulation
    # of the main body of the message *and* the key.
    encrypted_body = email_mime_multipart.MIMEMultipart('mixed')

    # First part of signed body
    textpart = email_mime_base.MIMEBase('text', 'plain', charset="ISO-8859-1")
    textpart.add_header('Content-Transfer-Encoding', 'quoted-printable')
    textpart.__delitem__('MIME-Version')
    textpart.set_payload(quoprimime.encode(
        self._get_email_body(signer, keyid, email)
    ))
    encrypted_body.attach(textpart)

    # The second part of the signed body
    file_base = os.path.basename(filename)
    attached_sig = email_mime_base.MIMEBase('application', 'pgp-keys',
                                     name='%s' % file_base)
    attached_sig.add_header('Content-Disposition', 'inline',
                            filename='%s' % file_base)
    attached_sig.__delitem__('MIME-Version')
    #
    # We USED to make this quoted-printable, but people with non-PGP-aware MUAs
    # were decrypting the body manually, and then trying to import the resulting
    # MIME message which was QP-encoded... so if there was an equals-sign in the
    # message, it would actually be an '=3D' and thus fail the import.
    #
    # RFC2015 strongly suggests using QP for any signed data to prevent MTAs
    # from messing with it... however, since this gets encrypted, this data is
    # never available for an MTA to mess with, so this ... should be safe, and
    # allows both methods of decrypting and importing the key.
    #
    # Side-note, if we ever turn to QP, be sure to use quoprimime.encode to
    # encode the payload.
    #
    attached_sig.set_payload(open(filename, 'r').read())
    encrypted_body.attach(attached_sig)

    encrypted_body.__delitem__('MIME-Version')

    # Encryt/Sign the MIME body.
    #
    # We have to conver to DOS newlines since that's what happens
    # to mail anyway and we don't want verification to fail
    dos_body = encrypted_body.as_string().replace('\n', '\r\n')
    tmpfile = os.path.join(self.tmp_dir, 'pius_tmp')
    signed_tmpfile = '%s.asc' % tmpfile
    clean_files([tmpfile, signed_tmpfile])
    tfile = open(tmpfile, 'w')
    tfile.write(dos_body)
    tfile.close()
    try:
      psigner.encrypt_and_sign_file(tmpfile, signed_tmpfile, keyid)
    except EncryptionKeyError:
      raise EncryptionKeyError

    # Create the version part of the PGP/Mime encryption
    pgp_ver = email_mime_base.MIMEBase('application', 'pgp-encrypted')
    pgp_ver.add_header('Content-Description', 'PGP/MIME version identification')
    pgp_ver.__delitem__('MIME-Version')
    pgp_ver.set_payload('Version: 1\n')

    # Create the big sign-encrypted body part
    pgp_data = email_mime_base.MIMEBase('application', 'octet-stream',
                                 name='encrypted.asc')
    pgp_data.add_header('Content-Description', 'OpenPGP encrypted message')
    pgp_data.add_header('Content-Disposition', 'inline',
                        filename='encrypted.asc')
    pgp_data.__delitem__('MIME-Version')
    pgp_data.set_payload(open(signed_tmpfile, 'r').read())

    # This is the actual encrypt-signed PGP/Mime message
    msg.attach(pgp_ver)
    msg.attach(pgp_data)

    clean_files([tmpfile, signed_tmpfile])
    return msg

  def _generate_non_pgp_mime_email(self, signer, email, keyid, filename):
    '''Send the encrypted uid off to the user.'''
    msg = email_mime_multipart()
    msg.epilogue = ''

    part = email_mime_text(self._get_email_body(signer, keyid, email))
    msg.attach(part)

    part = email_mime_base.MIMEBase('application', 'octet-stream')
    part.add_header('Content-Disposition', 'inline; filename="%s"' %
                    os.path.basename(filename))
    part.set_payload(open(filename, 'r').read())
    msg.attach(part)
    return msg

  def send_sig_mail(self, signer, keyid, uid_data, psign):
    '''Send the encrypted uid off to the user.'''
    try:
      if self.no_pgp_mime:
        msg = self._generate_non_pgp_mime_email(
            signer, uid_data['email'], keyid, uid_data['enc_file']
        )
      else:
        msg = self._generate_pgp_mime_email(
            signer, uid_data['email'], keyid, uid_data['file'], psign
        )
    except EncryptionKeyError:
      msg = ('Failed to generate the email to the user. This is most'
             ' likely due to the user having no encryption subkey.')
      raise MailSendError(msg)

    msg['Subject'] = 'Your signed PGP key'
    self._send_mail(uid_data['email'], msg)

  def send_mail(self, to, subject, body):
    '''Wrapper around _send_mail() which generates a Message object that it
       expects.'''
    msg = message.Message()
    msg.set_payload(body)
    msg['Subject'] = subject
    self._send_mail(to, msg)

  def _send_mail(self, to, msg):
    '''Given a to and Message object, send email.'''
    # We don't duplicate the header logic in the sub functions, we
    # do that here
    debug("send_mail called with to (%s), subject (%s)" % (to, msg['subject']))
    if self.display_name:
      msg['From'] = self.display_name + ' <' + self.mail + '>'
    else:
      msg['From'] = self.mail
    if self.address_override:
      msg['To'] = self.address_override
      env_to = [msg['To']]
    else:
      msg['To'] = to
      env_to = [msg['To'], self.mail]
    msg['Date'] = formatdate(localtime=True)

    if self.local_mail_dir:
      if not os.path.isdir(self.local_mail_dir):
        os.mkdir(self.local_mail_dir)
      if not self.address_override:
        msg['Bcc'] = self.mail
      email = open(os.path.join(self.local_mail_dir, msg['To']), 'w')
      email.write(str(msg))
      email.close()
    else:
      try:
        smtp = smtplib.SMTP(self.host, self.port)
        if self.tls:
          # NOTE WELL: SECURITY IMPORTANT NOTE!
          # In python 2.6 if you attempt to starttls() and the server doesn't
          # understand an exception is raised. However before that, it just
          # carried on # and one could attempt to auth over a plain-text session.
          # This is BAD!
          #
          # So, in order be secure on older pythons we ehlo() and then check the
          # response before attempting startls.
          smtp.ehlo()
          if not smtp.has_extn('STARTTLS'):
            # Emulate 2.6 behavior
            raise smtplib.SMTPException('Server does not support STARTTLS')
          smtp.starttls()
          # must re-ehlo after STARTTLS
          smtp.ehlo()
          # Don't want to send auth information unless we're TLS'd
          if self.user:
            smtp.login(self.user, self.password)
        if self.address_override:
          env_to = self.address_override
        else:
          # BCC the user...
          env_to = [msg['To'], self.mail]

        smtp.sendmail(self.mail, env_to, msg.as_string())
        smtp.quit()
      except smtplib.SMTPException as emsg:
        raise MailSendError(emsg)
      except socket.error as emsg:
        raise MailSendError(emsg)

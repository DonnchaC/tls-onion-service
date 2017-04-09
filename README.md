# TLS Onion Services for non-Tor users

This tool allows you to run an onion service and make it available over TLS for non-Tor users
via LetsEncrypt and the [OnionGateway](https://github.com/DonnchaC/oniongateway) proxy.

By default the tool uses the OnionGateway service running on https://oniongateway.com. A very limited
number of onion addresses are supported on this domain as it is not currently listed in the
Public Suffic List. Future production deployments will be in the Public Suffix List and enforce TLS
via the HSTS preload list.

## Running

```bash
$ ./tls-onion.py --test-run
2017-04-09 20:25:19,450 [INFO]: Starting ephemeral onion service, this may take a minute...
2017-04-09 20:25:53,825 [INFO]: Started ephemeral onion service 3nj7k3ww7xupn2bk
2017-04-09 20:25:53,825 [INFO]: Starting Flask server with self-signed certs for domain 3nj7k3ww7xupn2bk.oniongate.com
 * Running on https://127.0.0.1:8443/ (Press CTRL+C to quit)
2017-04-09 20:25:58,831 [INFO]: Starting LetsEncrypt cert request
2017-04-09 20:25:58,832 [DEBUG]: Running: certbot certonly --webroot -d 3nj7k3ww7xupn2bk.oniongate.com --register-unsafely-without-email --work-dir letsencrypt_data --config-dir letsencrypt_data --logs-dir letsencrypt_data --agree-tos -w webroot --keep --test-cert
127.0.0.1 - - [09/Apr/2017 20:26:07] "GET /.well-known/acme-challenge/WwYRTmwJcK6u8SnUdvEJuTfAAI1yJjlXunzZX-VvncA HTTP/1.1" 200 -
2017-04-09 20:26:11,708 [DEBUG]: Certbot output:
Saving debug log to /home/donnncha/Documents/Development/oniongateway/acme-client/letsencrypt_data/letsencrypt.log
Obtaining a new certificate
Performing the following challenges:
http-01 challenge for 3nj7k3ww7xupn2bk.oniongate.com
Using the webroot path /home/donnncha/Documents/Development/oniongateway/acme-client/webroot for all unmatched domains.
Waiting for verification...
Cleaning up challenges
Generating key (2048 bits): /home/donnncha/Documents/Development/oniongateway/acme-client/letsencrypt_data/keys/0004_key-certbot.pem
Creating CSR: /home/donnncha/Documents/Development/oniongateway/acme-client/letsencrypt_data/csr/0004_csr-certbot.pem
Non-standard path(s), might not work with crontab installed by your operating system package manager
IMPORTANT NOTES:
 - Congratulations! Your certificate and chain have been saved at
   /home/donnncha/Documents/Development/oniongateway/acme-client/letsencrypt_data/live/3nj7k3ww7xupn2bk.oniongate.com/fullchain.pem.
   Your cert will expire on 2017-07-08. To obtain a new or tweaked
   version of this certificate in the future, simply run certbot
   again. To non-interactively renew *all* of your certificates, run
   "certbot renew"

2017-04-09 20:26:11,709 [INFO]: Successfully got a LetsEncrypt cert for https://3nj7k3ww7xupn2bk.oniongate.com
2017-04-09 20:26:11,710 [INFO]: Starting Flask server with the LetsEncrypt certificate
 * Running on https://127.0.0.1:8443/ (Press CTRL+C to quit)
 * Running on http://127.0.0.1:8080/ (Press CTRL+C to quit)
```

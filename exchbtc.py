#!/usr/bin/Python
import hmac
import hashlib
import logging
import requests
import time
try:
	from urllib import urlencode

# for python3
except ImportError:
	from urllib.parse import urlencode


ENDPOINT = "https://www.exchbtc.com"

BUY = "BUY"
SELL = "SELL"

LIMIT = "LIMIT"
MARKET = "MARKET"

GTC = "GTC"
IOC = "IOC"

options = {}


def set(apiKey, secret):
	"""Set API key and secret.
	Must be called before any making any signed API calls.
	"""
	options["apiKey"] = apiKey
	options["secret"] = secret
	
def AllOrders(status, **kwargs):
	params = {"status":status}
	params.update(kwargs)
	data = signedRequest("GET", "/api/v7/allOrders", params)
	return data
	
def order(symbol, side, type, qty, price, newClientOrderID, **kwargs):
	params = {
		"symbol": symbol, 
		"side":side,
		"type": type,
		"quantity":qty,
		"price":price,
		"newClientOrderID":newClientOrderID
		}
	params.update(kwargs)
	data = signedRequest("GET", "/api/v7/order", params)
	return data
	
def exchangeInfo():
	params = {}
	data = signedRequest("GET", "/api/v7/exchangeInfo", params)
	return data
	
def balance(**kwargs):
	params = {}
	params.update(kwargs)
	data = signedRequest("GET", "/api/v7/balance", params)
	return data

def request(method, path, params=None):
	resp = requests.request(method, ENDPOINT + path, params=params)
	data = resp.json()
	if "msg" in data:
		logging.error(data['msg'])
	return data


def signedRequest(method, path, params):
	if "apiKey" not in options or "secret" not in options:
		raise ValueError("Api key and secret must be set")

	query = urlencode(sorted(params.items()))
	query += "&timestamp={}".format(int(time.time() * 1000)-500)
	print(query)
	secret = bytes(options["secret"].encode("utf-8"))
	signature = hmac.new(secret, query.encode("utf-8"),
						 hashlib.sha256).hexdigest()
	query += "&signature={}".format(signature)
	resp = requests.request(method,
							ENDPOINT + path + "?" + query,
							headers={"X-MBX-APIKEY": options["apiKey"]})
	print(resp.url)	
	data = resp.json()
	if "msg" in data:
		logging.error(data['msg'])
	return data

def formatNumber(x):
	if isinstance(x, float):
		return "{:.8f}".format(x)
	else:
		return str(x)

if __name__ == '__main__':
	apikey = 'b3f8cddfbff0f8c2d27b41cff6403fec33c87fd4f85379259955e25be7a6a6a1'
	secretkey = '4fcf58f6e4471124049f608c69acbb9b729f168ff341335d9e5af7ff495f59d6'
	set(apikey, secretkey)
	print(exchangeInfo())
	
	
	
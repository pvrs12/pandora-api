import blowfish
import requests
import json
import getpass
from time import time,sleep

nonhttps = 'http://internal-tuner.pandora.com/'
endpoint = 'https://internal-tuner.pandora.com/'
nonhttps2 = 'http://tuner.pandora.com/'
endpoint2 = 'https://tuner.pandora.com/'

resource = 'services/json/'
parameter = '?method='

partnerDecrypt = b'U#IO$RZPAB%VX2'
partnerEncrypt = b'2%3WCL*JU$MP]4'
dec_cipher = blowfish.Cipher(partnerDecrypt)
enc_cipher = blowfish.Cipher(partnerEncrypt)

def encrypt(body):
  while len(body) % 8 != 0:
    body += ' '
  enc_body = b"".join(enc_cipher.encrypt_ecb(bytes(body,'utf-8')))
  hex_body = ''.join('{:02x}'.format(x) for x in enc_body)
  return hex_body

def decrypt_syncTime(syncTime):
  syncTime = b"".join(dec_cipher.decrypt_ecb(bytearray.fromhex(syncTime)))
  syncTime = int(syncTime[4:-2])
  return syncTime

def checkLicensing():
  method = 'test.checkLicensing'
  url = nonhttps+resource+parameter+method
  r = requests.post(url)

def partnerAuth():
  initialTime = time()
  body = {
    "username":"pandora one",
    "password":'TVCKIBGS9AO9TSYLNNFUML0743LH82D',
    "deviceModel": "D01",
    "version": "5",
  }
  method = 'auth.partnerLogin'
  url = endpoint+resource+parameter+method
  r = requests.post(url,json=body);
  #print(r.text)

  resp = r.json()['result']
  syncTimeEnc = resp['syncTime']
  syncTime = decrypt_syncTime(syncTimeEnc)

  partnerToken = resp['partnerAuthToken']

  partnerId = resp['partnerId']
  return (int(initialTime) - syncTime,partnerToken,partnerId)

def userLogin(syncDiff, partnerToken, partnerId, username, password):
  body = {
    "loginType":"user",
    "username":username,
    "password":password,
    "partnerAuthToken":partnerToken,
    "returnStationList":True,
    "syncTime":int(time())+syncDiff
  }

  method = 'auth.userLogin'
  partnerIdParam = '&partner_id='+partnerId
  authTokenParam = '&auth_token='+partnerToken
  url = endpoint+resource+parameter+method+partnerIdParam+authTokenParam
  headers = {
    'Content-Type':'text/plain'
  }
  enc_json = encrypt(json.dumps(body))
  r = requests.post(url,data=enc_json)
  #print(r.text)
  try:
    resp = r.json()['result']
  except Exception:
    print(r.text)

  userToken = resp['userAuthToken']
  userId = resp['userId']

  stations = resp['stationListResult']['stations']

  return userToken,userId,stations

def getPlaylist(syncDiff,userToken,userId,partnerToken,partnerId,stationToken):
  body = {
    "stationToken":stationToken,
    "userAuthToken":userToken,
    "syncTime":int(time())+syncDiff
  }

  method = 'station.getPlaylist'
  partnerIdParam = '&partner_id='+partnerId
  userIdParam = '&user_id='+userId
  authTokenParam = '&auth_token='+partnerToken
  url = endpoint+resource+parameter+method+partnerIdParam+userIdParam+authTokenParam
  print(url)
  print(body)
  headers = {
    'Content-Type':'text/plain'
  }
  enc_json = encrypt(json.dumps(body))
  r = requests.post(url,data=enc_json)
  print(r.text)


#checkLicensing()
username = input('Username: ')
password = getpass.getpass('Password: ')
syncDiff,partnerToken,partnerId = partnerAuth()
userToken,userId,stations = userLogin(syncDiff,partnerToken,partnerId,username,password)
for i in range(len(stations)):
  print("{0} - {1}".format(i,stations[i]['stationName']))

print
station_num = int(input('Choose a station number to play: '))
getPlaylist(syncDiff,userToken,userId,partnerToken,partnerId,stations[station_num]['stationToken'])

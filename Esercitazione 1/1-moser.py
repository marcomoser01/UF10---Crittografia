import json, os
from base64 import b64encode, b64decode
from Crypto.Cipher import ChaCha20
from Crypto.Random import get_random_bytes
import tkinter as tk
from tkinter import filedialog
from Crypto.Cipher import AES

#custom error
class SymmetricChiperError(Exception):
  '''Error executing the script'''

class ValidationError(SymmetricChiperError):
    '''invalid input'''

prompt = '''What do you want to do?
  1 -> encrypt
  2 -> decrypt
  0 -> quit
  -> '''
promptMethod = '''Which method do you choose?
  1 -> No authentication
  2 -> Authentication
  0 -> quit
-> '''
promptKeyFilePath = 'What is the path to the key file?\t'
promptCtFilePath = 'What is the path to the cipher text file?\t'
promptPtFilePath = 'What is the path to the plain text file?\t'


def read_file(path, mode):
  try:
    with open(path, mode) as in_file:
      out_str = in_file.read()
  except IOError as e:
    raise SymmetricChiperError('\tError: Cannot read ' + path + ' file: ' + str(e))
  return out_str

def write_file(path, mode, data):
  try:
    with open(path, mode) as out_file:
      out_file.write(data)
  except IOError as e:
    raise SymmetricChiperError('\tError: Cannot write ' + data + ' in file: ' + path)

'''
  This method control if the path is a file/directory/new file/wrong insert
  parameters:
  - path: path to check
  returns:
    0 -> If is a regular existing file
    1 -> If is a regular existing directory
    2 -> If is a special file (socket, FIFO, device file) or wrong path
    3 -> If it is the path to a file to create
'''
def checkPath(path):
  state = -1

  if os.path.isfile(path):
    state = 0
    # normal file
  elif os.path.isdir(path):  
    state = 1
    # directory
  else:  
    state = 2
    # special file (socket, FIFO, device file) or wrong path
    
  if state == 2 and '.' in path[path.rfind('\\'):]:
    if os.path.isdir(path[:path.rfind('\\')]):
      state = 3
      # new file
        
  return state

'''
  The purpose of this function is to repeat the input of a path until checkPath returns an acceptable value
  parameters:
  - propt: the message to show in console
  - correctState: acceptable values as a result of checkPath. The parameter must be a string, like '03' if the 0 and 3 are acceptable valus 
  return the path and the state of checkPath
'''
def repeatCP(prompt, correctState):
  path = input(prompt)
  state = checkPath(path)
  while not str(state) in str(correctState):
    print('\tError: The path is not correct. Please try again!')
    path, state = repeatCP(prompt, correctState)
  return path, state


'''
  Encrypt the message using the chacha20 cipher and save the result in the specified file
'''
def encrypt(pt, keyFilePath, ctFilePath):
  key = get_random_bytes(32)
  write_file(keyFilePath, 'wb', key)
  
  cipher = ChaCha20.new(key=key)
  ciphertext = cipher.encrypt(pt)
  nonce = b64encode(cipher.nonce).decode('utf-8')
  ct = b64encode(ciphertext).decode('utf-8')
  
  result = json.dumps({'nonce':nonce, 'ciphertext':ct})
  write_file(ctFilePath, 'w', result)
  print('The ciphertext is: ' + ct)

'''
  Encrypt the message using the AES cipher in EAX mode and save the result in the specified file
'''
def encryptAuth(plaintext, keyFilePath, outFilePath):
  key = get_random_bytes(16)
  write_file(keyFilePath, 'wb', key)
  
  cipher = AES.new(key, AES.MODE_EAX)
  ciphertext, tag = cipher.encrypt_and_digest(str(plaintext).encode('ascii'))
  
  nonce = b64encode(cipher.nonce).decode('utf-8')
  ct = b64encode(ciphertext).decode('utf-8')
  tag = b64encode(tag).decode('utf-8')
  
  result = json.dumps({'nonce':nonce, 'ciphertext':ct, 'tag':tag})
  write_file(outFilePath, 'w', result)
  print('The ciphertext is: ' + ct)


'''
  Decrypt the message using the chacha20 cipher and print the result in console
'''
def decrypt(keyFilePath, jsonInFilePath):
  key = read_file(keyFilePath, 'rb')
  jsonInput = read_file(jsonInFilePath, 'r')
  
  try:
    b64 = json.loads(jsonInput)
    nonce = b64decode(b64['nonce'])
    ciphertext = b64decode(b64['ciphertext'])
    
    cipher = ChaCha20.new(key=key, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    print("The message was " + plaintext.decode('utf-8'))
  except (ValueError, KeyError):
    print("Incorrect decryption")

'''
  Decrypt the message using the AES cipher in EAX and print the result in console
'''
def decryptAuth(keyFilePath, jsonInFilePath):
  key = read_file(keyFilePath, 'rb')
  jsonInput = read_file(jsonInFilePath, 'r')
  
  try:
    nonce = b64decode(json.loads(jsonInput)['nonce'])
    ct = b64decode(json.loads(jsonInput)['ciphertext'])
    tag = b64decode(json.loads(jsonInput)['tag'])
  except:
    raise SymmetricChiperError('\tError: The ciphertext was not encrypted with authentication')
  
  cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
  try:
    plaintext = cipher.decrypt(ct).decode('utf-8').lstrip('b').strip("'")
    
    cipher.verify(tag)
    print("The message is authentic:", plaintext)
  except ValueError:
    print("Key incorrect or message corrupted")




# main
while True:

  choice = input(prompt)
  try:
    if choice == '1':
      
      ptFilePath = repeatCP(promptPtFilePath, '0')[0]   
      pt = read_file(ptFilePath, 'rb')
      
      choiceMethod = input(promptMethod)
      
      keyFilePath = repeatCP(promptKeyFilePath, '03')[0]
      ctFilePath, state = repeatCP(promptCtFilePath, '013')
      if(state == 1):
          ctFilePath += 'ciphertext.txt'
            
      if choiceMethod == '1':
        encrypt(pt, keyFilePath, ctFilePath)
        
      elif choiceMethod == '2':
        encryptAuth(pt, keyFilePath, ctFilePath)
        
    elif choice == '2':
      
      choiceMethod = input(promptMethod)
      
      keyFilePath = repeatCP(promptKeyFilePath, "0")[0]
      ctFilePath = repeatCP(promptCtFilePath, "0")[0]
        
      if choiceMethod == '1':
        decrypt(keyFilePath, ctFilePath)
      
      elif choiceMethod == '2':
        decryptAuth(keyFilePath, ctFilePath)
      
    elif choice == '0':
      exit()
      
    else:
      print('Invalid choice, please try again!')
      
  except SymmetricChiperError as e:
    print(e)
  print('\n\t\t--------------------------------------------------\n')
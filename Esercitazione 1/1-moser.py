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
  Questa funzione ripete la stessa operazione finchè non si ottiene il risultato desiderato, espresso in correctState
'''
def repeatCheckPathUntil(prompt, correctState):
  path = input(prompt)
  state = checkPath(path)
  while not str(state) in str(correctState):
    print('\tError: The path is not correct. Please try again!')
    state = repeatCheckPathUntil(prompt, correctState)[1]
  return path, state


def encrypt(plaintext):
  key = get_random_bytes(32)
  
  keyPath = repeatCheckPathUntil('What is the name of the file to save the key in: ', '03')[0]
  write_file(keyPath, 'wb', key)
  
  cipher = ChaCha20.new(key=key)
  ciphertext = cipher.encrypt(plaintext)
  nonce = b64encode(cipher.nonce).decode('utf-8')
  ct = b64encode(ciphertext).decode('utf-8')
  result = json.dumps({'nonce':nonce, 'ciphertext':ct})
  
  outputPath, state = repeatCheckPathUntil('Where you want save the ciphertext?', '013')
    
  if(state == 1):
      outputPath += 'ciphertext.txt'
  

  write_file(outputPath, 'w', result)
  print(result)

def decrypt():
  keyPath = repeatCheckPathUntil("In which file did you save the key", "0")[0]
  jsonInputPath = repeatCheckPathUntil("In which file did you save the cipher text", "0")[0]
  key = read_file(keyPath, 'rb')
  jsonInput = read_file(jsonInputPath, 'r')
  
  try:
    b64 = json.loads(jsonInput)
    nonce = b64decode(b64['nonce'])
    ciphertext = b64decode(b64['ciphertext'])
    cipher = ChaCha20.new(key=key, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    print("The message was " + plaintext.decode('utf-8'))
  except (ValueError, KeyError):
    print("Incorrect decryption")

def encryptAuth(data):
  key = get_random_bytes(16)
  cipher = AES.new(key, AES.MODE_EAX)
  nonce = cipher.nonce
  ciphertext, tag = cipher.encrypt_and_digest(data)
  print(ciphertext)
  decryptAuth(key, nonce, ciphertext, tag)

def decryptAuth(key, nonce, ciphertext, tag):
  cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
  plaintext = cipher.decrypt(ciphertext)
  try:
    cipher.verify(tag)
    print("The message is authentic:", plaintext.decode('utf-8'))
  except ValueError:
    print("Key incorrect or message corrupted")



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


# main
while True:

  choice = input(prompt)
  try:
    if choice == '1':
      
      choiceMethod = input(promptMethod)
      ptPath = repeatCheckPathUntil("Where is the plaintext path?", '0')[0]
      pt = read_file(ptPath, 'rb')
      
      if choiceMethod == '1':
        encrypt(pt)
        
      elif choiceMethod == '2':
        encryptAuth(pt)
        
    elif choice == '2':
      
      choiceMethod = input(promptMethod)
      
      if choiceMethod == '1':
        decrypt()
      
      elif choiceMethod == '2':
        decryptAuth()
      
    elif choice == '0':
      exit()
      
    else:
      print('Invalid choice, please try again!')
      
  except SymmetricChiperError as e:
    print(e)
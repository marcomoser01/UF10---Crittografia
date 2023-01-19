'''
    Scrivere un programma in python (python3) chiamato '1-cognome.py' (tutto minuscolo) che permetta la cifratura e decifratura di file arbitrari tramite cifrari simmetrici, usando la libreria PyCryptodome.
    L'utente inizia specificando se vuole cifrare o decifrare.
    L'utente deve poter specificare da input il percorso del file da cifrare/decifrare e del file dove salvare il risultato dell'operazione.
    L'utente deve poi poter selezionare se vuole includere o meno l'autenticazione dei dati cifrati. Il programma deve usare cifrari ed OM adeguati alla scelta (usate 2 cifrari diversi).
    In fase di cifratura la chiave va creata in maniera appropriata e poi salvata in chiaro in un file (il cui nome viene inserito dall'utente) situato nella stessa cartella del programma. Lo stesso file verrà letto in fase di decifratura (sempre chiedendo all'utente quale file usare).
    Il programma deve permettere più operazioni, finché l'utente non decide di uscire.
    Il programma deve gestire correttamente tutte le eccezioni che possono essere lanciate dai vari metodi, seguire pratiche crittografiche corrette, essere il più chiaro possibile (commentate a dovere).
'''


import os
from sys import platform
from getpass import getpass
from Crypto.Cipher import AES, DES3
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2


# custom errors
class SymEncError(Exception):
    '''Error executing Symmetric Encryption script'''
class ValidationError(SymEncError):
    '''invalid input'''


'''
  function that handles file input
  parameters:
  - prompt: message to display acquiring file path
  - validate: function that validates content read,
    should raise a ValidationError on invalid inputs
  tries to read valid content until success or user aborts
'''

def read_file(prompt, validate = lambda x : None):
    # repeat until a validated input is read or user aborts
    while True:
        # acquire file path
        path = input(prompt)
        # read input managing IOErrors
        try:
            # read content as bytes
            with open(path, 'rb') as in_file:
                content = in_file.read()
            try:
                # validate contents
                validate(content)
                # validation succesful, return content (end of function)
                return content
            except ValidationError as err:
                # print validation error
                print(err)
        except IOError as err:
            print('Error: Cannot read file ' + path + ': ' + str(err))
        # no valid content read: try again or abort
        choice = input('(q to abort, anything else to try again) ')
        if choice == 'q':
            raise SymEncError('Input aborted')



'''
  function that validates length
  parameters:
  data: byte string to check
  d_len: length in bytes the data must have
'''
def check_len(data, d_len):
  if len(data) != d_len:
    err_msg = 'Error: the data must be exactly '
    err_msg += k_len + ' bytes long, the input was '
    err_msg += len(data) + ' bytes long.'
    raise ValidationError(err_msg)



def clearConsole():
  if platform == "linux" or platform == "linux2":
    os.system("clear")
  elif platform == "darwin":
    os.system("clear")
  elif platform == "win32":
    os.system("cls")


#MAIN
clearConsole
while True:
  prompt = '''What do you want to do?
  1 -> encrypt
  2 -> decrypt
  3 -> clean console
  0 -> quit
 -> \t'''
  # get user's choice and call the appropriate function
  # errors are captured and printed out
  choice = input(prompt)
  try:
    if choice == '1':
      data16 = read_file(
        "Please insert path of a file containing 16 bytes: ",
        lambda data: check_len(data, 16)
      )
      encrypt()
    elif choice == '2':
      decrypt()
    elif choice == '3':
      clearConsole()
    elif choice == '0':
      exit()
    else:
        print('Invalid choice, please try again!')
  except OTPError as e:
    print(e)
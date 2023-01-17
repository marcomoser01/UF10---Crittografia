import os, string, ctypes

#alphabet, including space
alph = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 '

'''
  custom error
'''
class OTPError(Exception):
  '''Error executing OTP script'''

'''
  shift the first n letters to the end of alphabet, so we have "caesar alphabet"
  parameters:
  - n: number of shifts
  returns the "ceasar alphabet"
'''
def shift_alphabet(n):
    return alph[int(n):] + alph[0:int(n)]

'''
  read a text file following best practices
  parameters:
  - name: complete filename (including extensions)
      note that it should contain also the (relative) path
      if it is not located in the same folder as the one
      from which the script has been launched
      (usually the script's folder)
  returns the text contained in the file, without trailing newlines
'''
def read_file(name):
  try:
    # open in read mode a text file
    with open(name, 'r') as in_file:
      out_str = in_file.read()
  except IOError as e:
    raise OTPError('Error: Cannot read ' + name + ' file: ' + str(e))
  # delete possible trailing newlines
  return out_str.strip('\n')

'''
  check if there is at least one punctuation character in the parameter
  parameters:
  - data: string to check
  returns true if there isn't punctuation character otherwise false
'''
def correctInput(data):
  i = 0
  dataCorrect = True
  while i < len(str(data)) and dataCorrect:
    if data[i] in string.punctuation:
      dataCorrect = False
    i += 1
  return dataCorrect

'''
  function that performs caesar cipher encryption
'''
def encrypt():
  ptCorrect = False
  # read key from console
  key = input('Type how many letters you want to shift the alphabet:\n')
  try:
    int(key)
  except ValueError as e:
    raise OTPError(e)
    
  ceasar_alph = shift_alphabet(key)
  
  # read message from console
  while not ptCorrect:
    ptCorrect = True
    pt = input('Type message to encrypt:\n')
    if not correctInput(pt):
      ptCorrect = False
      print("The message must not contain punctuation")
  
  # encrypt
  ct = ''
  for s in pt:
    ct += ceasar_alph[alph.find(s)]
  # write output
  if ctypes.windll.user32.MessageBoxW(0, "Do you want to save the encrypted message in the ciphertext.txt file", "Save data", 4) == 6:
    try:
      with open('ciphertext.txt', 'w') as out_file:
        out_file.write(ct)
    except IOError as e:
      raise OTPError('Error: cannot write ciphertext: ' + str(e))
  # note that the following message is not printed if the function 
  # raised some exception previously
  print('\nEncrypted message correctly saved:\n' + ct + "\n")

'''
  function that performs caesar cipher decryption
'''
def decrypt():
  # read key from console
  key = input('How many letters had the alphabet been shifted by?')
  try:
    int(key)
  except ValueError as e:
    raise OTPError(e)
    
  ceasar_alph = shift_alphabet(key)
  
  # read ciphertext from file
  ct = read_file('ciphertext.txt')
  print('The ciphertext is:\n' + ct)
  
  # decrypt
  pt = ''
  for s in ct:
    pt += alph[ceasar_alph.find(s)]
  # write result on the console
  print('\nThe decrypted message is:\n' + pt + "\n")


os.system('cls')

# main
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
      encrypt()
    elif choice == '2':
      decrypt()
    elif choice == '3':
      os.system('cls')
    elif choice == '0':
      exit()
    else:
        print('Invalid choice, please try again!')
  except OTPError as e:
    print(e)
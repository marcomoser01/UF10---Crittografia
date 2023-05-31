# --Symmetric Encryption--

# import cryptography modules
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes
from getpass import getpass

# custom errors
class SymEncError(Exception):
    '''Error executing Symmetric Encryption script'''
class ValidationError(SymEncError):
    '''invalid input'''



def read_file(prompt, validate = lambda x : None):
    '''
        function that handles file input parameters:
        - prompt: message to display acquiring file path
        - validate: function that validates content read, should raise a ValidationError on invalid inputs 
        tries to read valid content until success or user aborts
    '''
    
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
                # validation successful, return content (end of function)
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

def write_file(prompt, data):
    '''
        function that handles file output
        parameters:
        - prompt: message to display acquiring file path
        - data: bytes to be written in file
        tries to write data until success or user aborts
    '''
    
    # repeat until  write or user aborts
    while True:
        # acquire file path
        path = input(prompt)
        # write input managing IOErrors
        try:
            # write content as bytes
            with open(path, 'wb') as out_file:
                out_file.write(data)
            return 'Data ly written in file "' + path + '".'
        except IOError as e:
            print('Error: Cannot write file ' + path + ': ' + str(e))
        # write unsuccessful: try again or abort
        choice = input('(q to abort, anything else to try again) ')
        if choice == 'q':
            raise SymEncError('Output aborted')



def gen_prompt(f_type, reading):
    '''
        function that generates prompts for reading and writing files
        parameters:
        - f_type: string that describes the file
        - read: boolean that tells if the prompt is for input or not
    '''
    
    message = "Please insert path of the file "
    if reading:
        message += "that contains the " + f_type
    else:
        message += "where to save the " + f_type
    return message + ": "



def encrypt(p_data, key = '', salt = ''):
    '''
        function that performs encryption
        parameters:
        - p_data: plaintext
    '''
    
    # encryption
    cipher = AES.new(key, AES.MODE_OCB)
    ciphertext, tag = cipher.encrypt_and_digest(p_data)
    c_data = salt + cipher.nonce + tag + ciphertext
    
    # output
    print(write_file(gen_prompt("encrypted data", False), c_data))


def check_c_len(data, c_len):
    '''
        function that validates ciphertext file length
        parameters:
        - data: byte string to check
        - c_len: length in bytes the key must have
    '''
    
    if len(data) < c_len:
        err_msg = 'Error: the ciphertext must be at least '
        err_msg += c_len + ' bytes long, the input was '
        err_msg += len(data) + ' bytes long.'
        raise ValidationError(err_msg)


def decrypt(c_data, key = ''):
    '''
        function that performs decryption
        parameters:
        - c_data: ciphertext
    '''
    
    # decryption
    nonce = c_data[16:31]
    tag = c_data[31:47]
    ciphertext = c_data[47:]
    cipher = AES.new(key, AES.MODE_OCB, nonce)
    try:
        p_data = cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError:
        raise SymEncError('Decryption error: authentication failure')
    
    # output
    print(write_file(gen_prompt("decrypted data", False), p_data))



def getKeyByPsw(psw, salt = ''):
    '''
        This method generate a key from a password
        Parameters:
        - psw: password
        - salt: if not specified or the length is incorrect it will generate a new 16 byte salt
        
        Returns:
        - the generated key and the salt
    '''
    
    if not isinstance(psw, str):
        raise TypeError("The argument 'psw' must be a string.")
    
    if len(salt) != 16:
        salt = get_random_bytes(16)
    key = scrypt(psw, salt, 16, N=2**14, r=8, p=1)
    return key, salt


# main
main_prompt = '''What do you want to do?
1 -> encrypt
2 -> decrypt
0 -> quit
-> '''

while True:
    # get user's choice and call appropriate function
    # errors are captured and printed out
    choice = input(main_prompt)
    try:
        if choice == '1':
            # read file to encrypt, no validation
            p_data = read_file(gen_prompt("data to encrypt", True))
            key, salt = getKeyByPsw(getpass('Password:'), '')
            encrypt(p_data, key, salt)
        elif choice == '2':
            c_data = read_file(gen_prompt("data to decrypt", True), lambda data: check_c_len(data, 47))
            key = getKeyByPsw(getpass('Password:'), c_data[:16])[0]
            
            decrypt(c_data, key)
        elif choice == '0':
            exit()
        else:
            # default error message for wrong inputs
            print('Invalid choice, please try again!')
    except SymEncError as e:
        print(e)



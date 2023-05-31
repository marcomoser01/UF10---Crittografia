'''
    GOAL:
    Scrivere un programma in python (python3) chiamato '3-cognome.py' (tutto minuscolo) che permetta di gestire
    uno scambio di file cifrati tramite cifratura ibrida.
    In particolare il programma deve gestire le seguenti operazioni:
    1) Creazione di chiavi asimmetriche: creare una coppia di chiavi RSA (pubblica/privata) rispettando le corrette
        pratiche di sicurezza. Le chiavi andranno poi salvate su file con nome a scelta dell'utente, proteggendo bene la chiave privata.
    2) Cifratura di file: cifrare un file seguendo uno schema di cifratura ibrida o di key encapsulation.
        L'utente deve poter cifrare un qualsiasi file, indicare un qualsiasi file contenente la chiave pubblica
        del destinatario, scegliere un qualsiasi nome per il file cifrato.
    3) Decifratura di file: decifrare un file ricavando la chiave di sessione tramite una propria chiave privata.
        L'utente deve poter scegliere un qualsiasi file da decifrare, indicare un qualsiasi file contenente la propria chiave privata,
        scegliere un qualsiasi nome per il file dove salvare il file decifrato.

    Il programma deve gestire correttamente tutte le eccezioni che possono essere lanciate dai vari metodi,
    seguire pratiche crittografiche corrette e le best practice viste in classe, essere il più chiaro possibile
    (commentate a dovere), evitare di avere codice duplicato.
'''

from genericpath import isfile
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from getpass import getpass


class HybEncError(Exception):
    '''Error executing Hybrid Encryption script'''


class ReadProcessingError(HybEncError):
    '''Error preprocessing data read from file'''


class InvalidKey(HybEncError):
    '''Invalid input key'''

class CryptMessage(HybEncError):
    '''Error encrypting or decrypting'''


def read_file(subject, error, default='', process=lambda data: data):
    '''
        Funtion that reads files\n
        Parameters:
            - subject: what the file should contain
            - error: error message to show when aborting
            - default: name of file to open if not specified
            - process: function to call on data, reading is not considered complete unless this function is called successfully.
            
        Should raise ReadProcessingError on errors\n    
        Returns data read (and processed) and name of file read
    '''

    # prepare string to print, including default choice
    prompt = 'Insert path to ' + subject + ' file'
    if default != '':
        prompt += ' (' + default + ')'
    prompt += ':\n'
    # try until file is correctly read or user aborts
    while True:
        # read choice, use default if empty
        in_filename = input(prompt)
        if in_filename == '':
            in_filename = default
        # read and process data
        try:
            with open(in_filename, 'rb') as in_file:
                data = in_file.read()
            return process(data), in_filename
        except (IOError, ReadProcessingError) as e:
            print('Error while reading '+subject+':\n'+str(e))
            # let user abort reading file
            c = input('q to quit, anything else to try again: ')
            if c.lower() == 'q':
                # abort
                raise HybEncError(error)

def write_file(data, subject, error, default=''):
    '''
        Function to write on file\n
        Parameters:
            - data: what to write to file
            - subject: description of what the file will contain
            - error: error message to show when aborting
            - default: name of file to open if not specified
        
        returns name of file written
    '''

    # try until file is correctly written or user aborts
    while True:
        # prepare string to print, including default choice
        prompt = 'Insert path to file where to save ' + subject
        if default != '':
            prompt += ' (' + default + ')'
        prompt += ':\n'
        # read choice, use default if empty
        out_filename = input(prompt)
        if out_filename == '':
            out_filename = default
        try:
            # warn before overwriting
            if isfile(out_filename):
                prompt = 'File exists, overwrite? '
                prompt += '(n to cancel, anything else to continue)\n'
                overwrite = input(prompt)
                if overwrite.lower() == 'n':
                    continue
            # write data
            with open(out_filename, 'wb') as out_file:
                out_file.write(data)
            return out_filename
        except IOError as e:
            print('Error while saving '+subject+': '+str(e))
            # let user abort writing file
            c = input('q to quit, anything else to try again: ')
            if c.lower() == 'q':
                # abort
                raise HybEncError(error)

def check_c_len(data, c_len):
    '''
        Function that validates ciphertext file length\n
        Parameters:
            - data: byte string to check
            - c_len: length in bytes the key must have
    '''

    if len(data) >= c_len:
        return data
    else:
        message = 'Error: the ciphertext must be at least '
        message += str(c_len) + ' bytes long.'
        raise ReadProcessingError(message)


def get_passphrase():
    '''
        Function that acquires a non-empty passphrase for private key protection
        Return: password if not empty
    '''

    prompt = "Insert password for the private key:"
    while True:
        pw = getpass(prompt)
        if pw != '':
            return pw
        else:
            prompt = "please enter a non-empty password:"


def keyGen(len=2048):
    '''
        Function that generates the private key\n
        Parameters:
            - len: integer with the default value of 2048 (Value may have to change in the future)

        Raise an InvalidKey if the key length is incorrect\n
        Return: an RSA key object with private and public key
    '''

    if len in {1024, 2048, 3072}:
        key = RSA.generate(len)

    else:
        raise InvalidKey('The number must be 1024, 2048 or 3072.')

    psw = get_passphrase()
    private_key = key.export_key('PEM', psw, 8, 'scryptAndAES128-CBC')
    public_key = key.public_key().export_key('PEM')

    key_saver(private_key, True)
    key_saver(public_key, False)
    return key


def key_saver(key, pub_priv: bool):
    '''
        Function that saves on a file the keys\n
        Parameters:
            - key: public or private key
            - pub_priv: boolean (true if priv, false if pub)
        
        Return: string, the path where the key was saved 
    '''

    if pub_priv:
        settings = {
            'data': key,
            'subject': 'encrypted private key',
            'error': 'Saving encrypted private key aborted.',
            'default': 'private.pem'
        }

    else:
        settings = {
            'data': key,
            'subject': 'public key',
            'error': 'Saving encrypted private key aborted.',
            'default': 'public.pem'
        }

    out_file = write_file(**settings)
    return out_file


def encrypt():
    '''
        Function encrypts a msg read from file with PKCS1_OAEP
    '''

    settings_rf_msg = {
        'subject': 'message to encrypt',
        'error': 'Reading encrypted file aborted',
        'default': 'msg.dec',
    }
    settings_rf_pub_key = {
        'subject': 'Public key',
        'error': 'Reading public key file',
        'default': 'public.pem',
        'process': lambda data: check_c_len(data, 256)
    }

    msg, _ = read_file(**settings_rf_msg)

    pub_key, _ = read_file(**settings_rf_pub_key)

    try:
        pub_key_imp = RSA.import_key(pub_key)
    except (ValueError, IndexError, TypeError) as e:
        raise InvalidKey('Invalid key: error importing public key | ' + str(e))

    cipher = PKCS1_OAEP.new(pub_key_imp)

    try:
        ciphertext = cipher.encrypt(msg)
    except (ValueError, TypeError) as e:
        raise CryptMessage('CryptMessage: Error during the encription | ' + str(e))

    settings_write_file = {
        'data': ciphertext,
        'subject': 'ciphertext',
        'error': 'Writing ciphertext aborted',
        'default': 'msg.enc'
    }
    write_file(**settings_write_file)


def decrypt():
    '''
        Function that takes the encrypted message and decrypts it then it saves the result on a file
        
        Rreturn: the plain message
    '''

    settings_rf_enc_msg = {
        'subject': 'Encrypted file',
        'error': 'Reading enc_file aborted',
        'default': 'msg.enc',
    }
    settings_rf_priv_key_enc = {
        'subject': 'private key',
        'error': 'Error reading the private key file',
        'default': 'private.pem',
        'process': lambda data: check_c_len(data, 256)
    }

    enc_msg, _ = read_file(**settings_rf_enc_msg)
    priv_key_enc, _ = read_file(**settings_rf_priv_key_enc)

    try:
        priv_key = RSA.import_key(priv_key_enc, get_passphrase())
    except (ValueError, IndexError, TypeError) as e:
        raise InvalidKey('Invalid key: ' + str(e))

    cipher = PKCS1_OAEP.new(priv_key)

    try:
        plaintext = cipher.decrypt(enc_msg)
    except (ValueError) as e:
        raise CryptMessage('Crypt Message: Error during the decription | ' + str(e))
    except (TypeError) as e:
        raise InvalidKey('Invalid key: ' + str(e))

    settings_write_file = {
        'data': plaintext,
        'subject': 'Decrypted message',
        'error': 'Decryption abort',
        'default': 'msg.dec'
    }
    write_file(**settings_write_file)

    return plaintext


def main():
    '''
        Func is the main of the program
    '''

    main_prompt = '''What do you want to do?
    1 -> Encrypt
    2 -> Decrypt
    3 -> RSA key generation
    0 -> Quit
    -> '''

    while True:
        # get user's choice and call appropriate function
        # errors are captured and printed out
        choice = input(main_prompt)
        try:
            if choice == '1':
                encrypt()

            elif choice == '2':
                decrypt()

            elif choice == '3':
                keyGen(2048)

            elif choice == '0':
                exit()

            else:
                # default error message for wrong inputs
                print('Invalid choice, please try again!')
        except HybEncError as e:
            print(e)

'''
    start
    Python Best Practice
    Checks what's running the script and, if it's just imported functions, it doesn't run the main method.
'''
if __name__ == '__main__':
    main()

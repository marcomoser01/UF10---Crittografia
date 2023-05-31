#!/usr/bin/python3
# --Digital Signature--


# import modules
from Crypto.Signature import eddsa
from Crypto.PublicKey import ECC
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from base64 import b64decode
from getpass import getpass
from os.path import isfile
import json


# custom errors

class DSSErrorr(Exception):
    '''Error executing DSS script'''
class ReadProcessingError(DSSErrorr):
    '''Error preprocessing data read from file'''
class HybEncError(Exception):
    '''Error executing Hybrid Encryption script'''

class IO_Function:
    '''
        INPUT/OUTPUT functions
    '''

    def read_file(subject, error, default='', process=lambda data: data):
        '''
            funtion that reads files
            parameters:
            - subject: what the file should contain
            - error: error message to show when aborting
            - default: name of file to open if not specified
            - process: function to call on data,
                reading is not considered complete unless
                this function is called successfully.
                Should raise ReadProcessingError on errors
            returns data read (and processed) and name of file read
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
                    raise DSSErrorr(error)

    def write_file(data, subject, error, default=''):
        '''
            function to write on file
            parameters:
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
                    raise DSSErrorr(error)

class Certificate:
    
    # CERTIFICATE Functions
    
    def gen_cert():
        '''
            function that creates a certificate with the provided public key and name
            it leaves the sig field empty as per requested
        '''
        pk = read_key(False).exportKey('PEM').decode('utf8')
        name = input('Certificate id: ')
        settings = {
            'data': json.dumps({'id': name, 'pubk': pk,
                                'sig': ''}).encode('utf8'),
            'subject': 'certificate',
            'error': 'Output aborted',
            'default': name+'.cert'
        }
        out_file = IO_Function.write_file(**settings)
        print('Certificate correctly generated: "' + out_file + '"')
        
    def ver_sig(msg, sig, pub_key):
        '''
            function that verifies a signature
            parameters:
            - msg: byte string to verify
            - sig: byte string containing the signature to be checked
            - pub_key: imported public key
            raises an exception if the signature does not verify
            against msg and pub_key
        '''
        # initialise verifying
        verifier = eddsa.new(pub_key, 'rfc8032')
        # verify
        try:
            verifier.verify(msg, sig)
        except ValueError:
            print('Invalid signature!')
            raise ValueError()

    def import_cert(data):
        '''
            function that imports and validates a certificate
            parameters:
            - data: byte string to check and import
        '''
        
        error_msg = 'Certificate format not valid: '
        try:
            # decode as string and import as json
            cert = json.loads(data)
            # get values to sign
            info = [cert['id'], cert['pubk']]
            if 'sig' in cert:
                info += [b64decode(cert['sig'])]
        except ValueError:
            error_msg += 'encoding error.'
            raise ReadProcessingError(error_msg)
        except TypeError:
            error_msg += 'invalid data.'
            raise ReadProcessingError(error_msg)
        except KeyError as e:
            # certificate does not have 'id' or 'pubk' fields
            error_msg += str(e) + ' field not found.'
            raise ReadProcessingError(error_msg)
        return info

    def cert_sig_enc(info):
        '''
            function that prepares certificate data for signing
        '''
        
        return info[0].encode('utf-8') + info[1].encode('utf-8')

    def verify_cert():
        '''
            function that verifies a certificate
            returns the public key contained in the certificate
        '''
        # public key to use
        pk = ECC.import_key("""-----BEGIN PUBLIC KEY-----
        \nMCowBQYDK2VwAyEA6nUBRM22wgeqVm/GkPlimdbsjaofC4Sk4eQ4ebhEjTs=\n
        -----END PUBLIC KEY-----""")
        # read certificate to verify
        settings = {
            'subject': 'certificate to verify',
            'error': 'Verification aborted.',
            'process': Certificate.import_cert
        }
        done = False
        while (done == False):
            info, _ = IO_Function.read_file(**settings)
            if len(info) < 3:
                # 'sig' field is missing
                print('The Certificate is not signed!')
                return
            # verify signature of certificate against public key
            try:
                Certificate.ver_sig(Certificate.cert_sig_enc(info), info[2], pk)
                print('OK: the certificate is valid.')
                done = True
            except ValueError:
                print('The certificate is not valid!')
                c = input('q to quit, anything else to try again: ')
                if c.lower() == 'q':
                    # abort
                    raise DSSErrorr()

        return info[1]


default_private_key = 'RSA_sk.pem'
default_public_key = 'RSA_pk.pem'


#
# VALIDATION FUNCTIONS
#

def check_len(data, min_len):
    '''
        function that validates a file's minimum length
        parameters:
        data: byte string to check
        min_len: minimum length in bytes the file must have
    '''
    
    if len(data) >= min_len:
        return data
    else:
        message = 'Error: the file must be at least '
        message += str(min_len) + ' bytes long.'
        raise ReadProcessingError(message)

def import_key(data, is_private):
    '''
        function that imports and validates an RSA key
        parameters:
        - data: byte string to check and import
        - private: boolean that tells if the key should be a private key
    '''
    
    passphrase = None
    if is_private:
        # aquire passphrase
        prompt = "Insert password to unlock the private key:"
        passphrase = getpass(prompt)
    # import key
    try:
        key = RSA.import_key(data, passphrase=passphrase)
    except ValueError as e:
        # error message
        message = 'Error while importing the key: ' + str(e)
        if is_private:
            message += '\nPlease check that the password is correct.'
        raise ReadProcessingError(message)
    # check size
    if key.size_in_bytes() < 256:
        message = f'Error: RSA size insufficient, '
        message += f'should be at least 256 bytes.'
        raise ReadProcessingError(message)
    # check type
    if is_private and (not key.has_private()):
        raise ReadProcessingError('Error: this is not a private key!')

    return key

#
# SUPPORT FUNCTIONS
#

def get_passphrase():
    '''
        function that acquires a non-empty passphrase
        for private key protection
    '''
    
    prompt = "Insert password for the private key:"
    while True:
        pw = getpass(prompt)
        if pw != '':
            return pw
        else:
            prompt = "please enter a non-empty password:"

def read_key(is_private):
    '''
        function that imports a key from file
        parameters:
        - private: boolean that tells if the key is private
        returns the imported key
    '''
    
    # prepare settings
    settings = {
        'error': 'Key import aborted.',
        'process': lambda data: import_key(data, is_private)
    }
    if is_private:
        settings['subject'] = 'private key'
        settings['default'] = default_private_key
    else:
        settings['subject'] = 'public key'
        settings['default'] = default_public_key

    key, _ = IO_Function.read_file(**settings)
    return key

#
# GENERATE KEYS
#

def gen_keys():
    # generate key pair
    key = RSA.generate(2048)
    print('Keys generated!')
    # export private key
    # acquire passphrase
    passphrase = get_passphrase()
    # define export settings
    export_settings = {
        'format': 'PEM',
        'pkcs': 8,
        'passphrase': passphrase,
        'protection': 'scryptAndAES128-CBC'
    }
    # export
    private_key = key.export_key(**export_settings)
    # save on file
    settings = {
        # PEM is a textual format, so we encode it as raw bytes
        'data': private_key,
        'subject': 'private key',
        'error': 'Output aborted.',
        'default': default_private_key
    }
    out_file = IO_Function.write_file(**settings)
    print('Private key correctly written in "' + out_file + '"')
    # export public key
    public_key = key.public_key().export_key(format='PEM')
    # save on file
    settings = {
        'data': public_key,
        'subject': 'public key',
        'default': default_public_key
    }

    # complete export settings and write file
    name = settings['subject'].capitalize()
    settings['error'] = name + ' not saved: aborted.'
    out_file = IO_Function.write_file(**settings)
    print(name + ' correctly written in "' + out_file + '"')


# ENCRYPTION FUNCTIONS


def encrypt():
    '''
        # function that performs encryption
    '''
    # read ceritifcate to import
    info = Certificate.verify_cert()

    # read file to encrypt, no validation
    settings = {
        'subject': 'data to encrypt',
        'error': 'Plaintext reading aborted.'
    }

    p_data, in_file = IO_Function.read_file(**settings)

    # file encryptionimport_key
    aes_key = get_random_bytes(16)
    aes_cipher = AES.new(aes_key, AES.MODE_OCB)
    ciphertext, tag = aes_cipher.encrypt_and_digest(p_data)
    
    # key encryption
    # errors not captured because of previous checks on pk
    rsa_cipher = PKCS1_OAEP.new(import_key(info, False))
    enc_key = rsa_cipher.encrypt(aes_key)
    
    # output
    settings = {
        'data': enc_key + aes_cipher.nonce + tag + ciphertext,
        'subject': 'ciphertext',
        'error': 'Output aborted.',
        'default': in_file + '.enc'
    }
    out_file = IO_Function.write_file(**settings)
    print('Ciphertext correctly written in "' + out_file + '"')

def decrypt():
    '''
        function that performs decryption
    '''
    # read private key to use
    settings = {
        'subject': 'private key',
        'error': 'Key import aborted.',
        'default': default_private_key,
        'process': lambda data: import_key(data, True)
    }
    rsa_sk, _ = IO_Function.read_file(**settings)

    # read file to decrypt, validating length
    rsa_size = rsa_sk.size_in_bytes()
    min_c_len = rsa_size + 15 + 16
    settings = {
        'subject': 'data to decrypt',
        'error': 'Ciphertext reading aborted.',
        'process': lambda data: check_len(data, min_c_len)
    }
    c_data, in_file = IO_Function.read_file(**settings)
    
    # decomposition
    enc_key = c_data[: rsa_size]
    nonce = c_data[rsa_size: rsa_size + 15]
    tag = c_data[rsa_size + 15: min_c_len]
    ciphertext = c_data[min_c_len:]

    # key decryption
    # some errors are not captured because of previous checks on sk
    rsa_cipher = PKCS1_OAEP.new(rsa_sk)
    try:
        aes_key = rsa_cipher.decrypt(enc_key)
    except ValueError:
        raise HybEncError('Decryption error: please check private key')
    
    # ciphertext decryption
    aes_cipher = AES.new(aes_key, AES.MODE_OCB, nonce)
    try:
        p_data = aes_cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError:
        raise HybEncError('Decryption error: authentication failure')
    
    # output
    # try to deduce original filename
    if in_file[-4:] == '.enc':
        default = in_file[:-4]
    else:
        default = ''
        
    # write output
    settings = {
        'data': p_data,
        'subject': 'decrypted data',
        'error': 'Output aborted.',
        'default': default
    }
    out_file = IO_Function.write_file(**settings)
    print('Decrypted data correctly written in "' + out_file + '"')


#
# MAIN
#
main_prompt = '''What do you want to do?
1 -> generate and save keys
2 -> generate a certificate
3 -> encrypt a file
4 -> decrypt a file
0 -> quit
-> '''
while True:
    # get user's choice and call appropriate function
    # errors are captured and printed out
    # invalid choices are ignored
    choice = input(main_prompt)
    try:
        if choice == '1':
            gen_keys()
        elif choice == '2':
            Certificate.gen_cert()
        elif choice == '3':
            encrypt()
        elif choice == '4':
            decrypt()
        elif choice == '0':
            exit()
    except DSSErrorr as e:
        print(e)

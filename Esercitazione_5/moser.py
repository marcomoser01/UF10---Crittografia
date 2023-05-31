from getpass import getpass
from Crypto.Hash import BLAKE2b
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
import json
import os.path


def load_data(path, password):
    '''
        Load encrypted data from a file and decrypt it.

        parameters:
            - path (str): Path to the file containing the encrypted data.
            - password (str): Password to derive the key for decrypting the data.

        returns:
            - The decrypted data as a Python dictionary.

        raises:
            IOError: If the data is not valid JSON or the decryption fails.
    '''
    
    with open(path, 'rb') as in_file:
        salt = in_file.read(16)
        nonce = in_file.read(15)
        tag = in_file.read(16)
        ciphertext = in_file.read(-1)
        
    key = scrypt(password, salt, 16, N=2**20, r=8, p=1)
    cipher = AES.new(key, AES.MODE_OCB, nonce)
    data = cipher.decrypt_and_verify(ciphertext, tag)

    try: 
        credentials = json.loads(data.decode('utf-8'))
    except ValueError as err:
        raise IOError(f'data not valid: {str(err)}')
    return credentials

def save_and_exit(path, password, credentials):
    '''
        Encrypt and save data to a file.

        parameters:
            - path (str): Path to the file to save the encrypted data.
            - password (str): Password to derive the key for encrypting the data.
            - credentials (dict): Data to be encrypted and saved.
    '''
    data = json.dumps(credentials, ensure_ascii=False).encode('utf-8')
    
    salt = get_random_bytes(16)
    key = scrypt(password, salt, 16, N=2**20, r=8, p=1)
    cipher = AES.new(key, AES.MODE_OCB)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    
    with open(path, 'wb') as out_file:
        out_file.write(salt)
        out_file.write(cipher.nonce)
        out_file.write(tag)
        out_file.write(ciphertext)

def search_and_add(query, dic):
    '''
        Searches for the given query in the provided dictionary and prints the corresponding username and password if found. 
        If the query is not found, the user is prompted to add a new entry. 
        If the user confirms, a new entry is added to the dictionary with the query as the key and the provided username and password as values.

        parameters:
            - query (str): The query to search for in the dictionary.
            - dic (Dict[str, Dict[str, str]]): The dictionary to search for the query and to add new entries if required.

        returns:
            - Dict[str, Dict[str, str]]: The updated dictionary with the new entry added, if any.
    '''
    if query in dic:
        print('username: ', dic[query]['username'])
        print('password: ', dic[query]['password'])
    else:
        prompt = 'Credentials not found. Add new entry?'
        prompt += '\n(y to continue, anything else to cancel)\n'
        add = input(prompt)
        if add == 'y':
            username_n = input('Insert username: ')
            password_n = getpass('Insert password: ')
            dic[query] = {
                    'username': username_n,
                    'password': password_n
                    }
    return dic

def log_in(username, password):
    '''
        Logs the user in by loading their encrypted credentials and prompting them to
        search for a specific set of credentials or to add new ones. If the user doesn't
        exist, it prompts them to sign up and create new credentials. Once the user is
        done searching for credentials or adding new ones, it saves the updated credentials
        to the file.
        
        parameters:
            - username (str): the username of the user to log in
            - password (str): the password to decrypt the user's credentials
    '''
    blake_hash = BLAKE2b.new(data = username.encode('utf-8'), digest_bytes=64)
    path_file = blake_hash.hexdigest()
    
    if os.path.exists(path_file):        
        try:
            credentials = load_data(path_file, password)
        except ValueError as err:
            print('Autentication failed')
            return
        except IOError as err:
            print('Error loading data:')
            print(err)
            return
        
    else:
        prompt = 'User not found. Add as new?'
        prompt += '\n(y to continue, anything else to cancel)\n'
        sign_up = input(prompt)
        if sign_up == 'y':
            credentials = {}
        else:
            return
    
    prompt = 'Credentials to search:'
    prompt += '\n(leave blank and press "enter" to save and exit)\n'
    while True:
        query = input(prompt)
        if query != '':
            credentials = search_and_add(query, credentials)
        else:
            try:
                print('Saving data...')
                save_and_exit(path_file, password, credentials)
                print('Data saved!')
            except IOError:
                print('Error while saving, new data has not been updated!')
            return



def main():
    while True:
        print('Insert username and password to load data,')
        print('leave blank and press "enter" to exit.')
        username = input('Username: ')
        if username == '':
            print('Goodbye!')
            exit()
        else:
            # leggi la password in maniera opportuna
            password = getpass('Password: ')
            log_in(username, password)

'''
    start
    Python Best Practice
    Checks what's running the script and, if it's just imported functions, it doesn't run the main method.
'''
if __name__ == '__main__':
    main()
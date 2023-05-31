from Crypto.Random import get_random_bytes

class HybEncError(Exception):
    '''Error executing Hybrid Encryption script'''

class ReadProcessingError(HybEncError):
    '''Error preprocessing data read from file'''


#
# INPUT/OUTPUT functions
#


# funtion that reads files
# parameters:
# - subject: what the file should contain
# - error: error message to show when aborting
# - default: name of file to open if not specified
# - process: function to call on data,
#       reading is not considered complete unless
#       this function is called successfully.
#       Should raise ReadProcessingError on errors
# returns data read (and processed) and name of file read


def read_file(subject, error, default='', process=lambda data: data):
    #prepare string to print, including default choice
    prompt = 'Insert path to ' + subject + ' file'
    if default != '':
        prompt += ' (' + default + ')' 
    prompt += ':\n'
    #try until file is correctly read or user aborts
    while True:
        #read choice, use default if empty
        in_filename = input(prompt)
        if in_filename  == '':
            in_filename  = default
        #read and process data
        try:
            with open(in_filename, 'rb') as in_file:
                data = in_file.read()
            return process(data), in_filename
        except (IOError, ReadProcessingError) as e:
            print('Error while reading '+subject+':\n'+str(e))
            #let user abort reading file
            c = input('q to quit, anything else to try again: ')
            if c.lower() == 'q':
                #abort
                raise HybEncError(error)

# function to write on file
# parameters:
# - data: what to write to file
# - subject: description of what the file will contain
# - error: error message to show when aborting
# - default: name of file to open if not specified
# returns name of file written


def write_file(data, subject, error, default=''):  
    #try until file is correctly written or user aborts
    while True:
        # prepare string to print, including default choice
        prompt = 'Insert path to file where to save ' + subject
        if default != '':
            prompt += ' (' + default + ')' 
        prompt += ':\n'
        # read choice, use default if empty
        out_filename = input(prompt)
        if out_filename  == '':
            out_filename  = default
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



#
# VALIDATION FUNCTIONS
#


# function that validates ciphertext file length
# parameters:
# data: byte string to check
# c_len: length in bytes the key must have


def check_c_len(data, c_len):
    if len(data) >= c_len:
        return data
    else:
        message = 'Error: the ciphertext must be at least '
        message += str(c_len) + ' bytes long.'
        raise ReadProcessingError(message)

# save on file
settings = {
    'data': get_random_bytes(10),
    'subject': '10 random bytes',
    'error': 'Output aborted.',
    'default': 'rnd10'
}
out_file = write_file(**settings)

# read public key to use
settings = {
    'subject': 'random bytes',
    'error': 'random import aborted.',
    'default': 'rnd10',
    'process': lambda data: check_c_len(data, 10)
}
rnd, _ = read_file(**settings)


# function that acquires a non-empty passphrase
# for private key protection

def get_passphrase():
    prompt = "Insert password for the private key:"
    while True:
        pw = getpass(prompt)
        if pw != '':
            return pw
        else:
            prompt = "please enter a non-empty password:"


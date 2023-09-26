import PySimpleGUI as sg
from IDEA import IDEA
from ECDSA import ECDSA
from MHKS import MerkleHellmanKnapsack 

# Create an instance of the IDEA class with a 128-bit key
IDEA_key = 0x2BD6459F82C5B300952C49104881FF48
# The IDEA key encrypted with the Merkle-Hellman Knapsack public key
encrypted_IDEA_key = 0
# The IDEA key signed with ECDSA
ECDSA_signature = 0
# The initialization vector
iv = 0x0000000000000000

# Create an instance of the MerkleHellmanKnapsack class
mhks = MerkleHellmanKnapsack()

# Create an instance of the ECDSA class
ecdsa = ECDSA()

def handleMerkleHellmanKey(key):
    if len(key) > 0:
        return int(values["-MH_PUBLIC_KEY-"], 16)
    return 0

def handleInitilizationVector(iv):
    if len(iv) > 0:
        iv = int(''.join(format(ord(c), '08b') for c in iv), 2) & 0xFFFFFFFFFFFFFFFF
        # We increase the IV by one in order to insure 64 bit size
        iv += 1
        return iv & 0xFFFFFFFFFFFFFFFF
    return 0x0000000000000000

def IdeaEncryption(plaintext, key):
    idea = IDEA(key, iv)
    enc_text = idea.encrypt(plaintext)
    return enc_text

def IdeaDecryption(ciphertext, key):
    idea = IDEA(key, iv)
    dec_text = idea.decrypt(ciphertext)
    return dec_text

def throwAuthenticationError(error):
    window["-PLAINTEXT-"].update(error)


sg.theme('SystemDefaultForReal')

# First the window layout in 2 columns
encryption_column = [
    [
        sg.Text("Plaintext"),
        
    ],
    [
        sg.Multiline(size=(60, 10), key="-PLAINTEXT-")
    ],
    [
        sg.Button("Encrypt", size=(10, 1)),
        sg.Button("Clear", key='-PLAIN_CLEAR-'),
        sg.Button("Copy", key='-PLAIN_COPY-'),
        # sg.FileBrowse(key="-IMPORT_TXT-")
        sg.Input(key='-IMPORT_TXT-', visible=False, enable_events=True), sg.FileBrowse()
    ],
    [   
        sg.Text("Decryption Verified: "),
        sg.Text("False", size=(40, 1), key="-VERIFIED-", tooltip="Verified", font=("Helvetica", 10), text_color="red"),
    ],
    [
        sg.Text("IDEA Key: "),
        sg.Push(),
        sg.Input("0x2BD6459F82C5B300952C49104881FF48", size=(40, 1), key="-IDEA_KEY-", tooltip="Idea Key", font=("Helvetica", 10)),
        sg.Button("Copy", key="-IDEA_KEY_COPY-"),

    ],
    [
        sg.Text("Initialization String (Optional)"),
        sg.VSeparator(),
        sg.Text("Current: " + str(hex(iv)), key="-CURRENT_IV-"),
    ],
    [
        sg.Input(size=(40, 1), key="-IV-"),
    ],
    
]
# First the window layout in 2 columns
decryption_column = [
    [
        sg.Text("Ciphertext"),
        
    ],
    [
        sg.Multiline(size=(60, 10), key="-CIPHERTEXT-")
    ],
    [
        sg.Button("Decrypt", size=(10, 1)),
        sg.Button("Clear", key='-CIPHER_CLEAR-'),
        sg.Button("Copy", key='-CIPHER_COPY-'),
    ],
    [
        sg.Text("Signature: "),
        sg.Push(),
        sg.Input(size=(40, 1), key="-SIGNATURE-", tooltip="Signature", font=("Helvetica", 10)),
        sg.Button("Copy", key="-SIGNATURE_COPY-"),
    ],
    [
        sg.Text("Public Key: "),
        sg.Push(),
        sg.Input(size=(40, 1), key="-MH_PUBLIC_KEY-", tooltip="Public Key", font=("Helvetica", 10)),
        sg.Button("Copy", key="-MH_PUBLIC_KEY_COPY-"),

    ],
    [
        sg.Text("Initialization String (Optional)"),
        sg.VSeparator(),
        sg.Text("Current: " + str(hex(iv)), key="-CURRENT_DECRYPTION_IV-"),
    ],
    [
        sg.Input(size=(40, 1), key="-DECRYPTION_IV-"),
    ],
    [
        sg.Button("Export Encryption")
    ]
]

# GUI Layout
layout = [
    [
        sg.vtop(sg.Column(encryption_column)),
        sg.VSeperator(),
        sg.vtop(sg.Column(decryption_column)),
    ],

]

# Create the window
window = sg.Window("IDEA Encryption/Decryption CBC Mode", layout, margins=(10, 20))

# Event loop
while True:
    event, values = window.read() 

    if event == sg.WINDOW_CLOSED:
        break

    elif event == "-IMPORT_TXT-":
        path = values["-IMPORT_TXT-"]
        try:
            with open(path, "r") as file:
                content = file.read()
            window["-PLAINTEXT-"].update(content)
        except FileNotFoundError:
            sg.popup_error("File not found.")

    elif event == "Encrypt":
        iv_text = values["-IV-"]
        iv = handleInitilizationVector(values["-IV-"])
        IDEA_key = int(values["-IDEA_KEY-"], 16)

        plaintext = values["-PLAINTEXT-"]
        # Encrypt IDEA plaintext
        ciphertext = IdeaEncryption(plaintext, IDEA_key)
        # Encrypt IDEA key using Merkle-Hellman knapsack
        encrypted_IDEA_key = mhks.encrypt(IDEA_key)
        # Sign the encrypted key using ECDSA
        ECDSA_signature = ecdsa.sign(encrypted_IDEA_key)

        window["-CURRENT_IV-"].update("Current: " + str(hex(iv)))
        window["-CURRENT_DECRYPTION_IV-"].update("Current: " + str(hex(iv)))
        window["-DECRYPTION_IV-"].update(iv_text)
        window["-CIPHERTEXT-"].update(ciphertext.encode("utf-8").hex())
        window["-SIGNATURE-"].update(ECDSA_signature.hex())
        window["-MH_PUBLIC_KEY-"].update(str(hex(encrypted_IDEA_key)))

    elif event == "Decrypt": 
        iv = handleInitilizationVector(values["-DECRYPTION_IV-"])
        ciphertext = bytes.fromhex(values["-CIPHERTEXT-"]).decode("utf-8")
        signature = bytes.fromhex(values["-SIGNATURE-"])  
        MHKS_public_key = handleMerkleHellmanKey(values["-MH_PUBLIC_KEY-"])
        if len(signature) != 64 or MHKS_public_key == 0:
            throwAuthenticationError("Decryption error: Invalid key or signature.")
        else:
            # Verify signature
            is_verified = ecdsa.verify(MHKS_public_key, signature)
            if not is_verified:
                throwAuthenticationError("Authentication error: The verification process failed.")
                window["-VERIFIED-"].update(str(is_verified), text_color="red")
            else:
                # Decrypt IDEA key using Merkle-Hellman knapsack
                decrypted_key = mhks.decrypt(MHKS_public_key)
                # Decrypt IDEA ciphertext
                plaintext = IdeaDecryption(ciphertext, decrypted_key)
                window["-PLAINTEXT-"].update(plaintext)
                window["-VERIFIED-"].update(str(is_verified), text_color="green")


            window["-CURRENT_DECRYPTION_IV-"].update("Current: " + str(hex(iv)))

    elif event == '-CIPHER_COPY-':
        text_to_copy = values['-CIPHERTEXT-']
        sg.clipboard_set(text_to_copy)
    
    elif event == '-PLAIN_COPY-':
        text_to_copy = values['-PLAINTEXT-']
        sg.clipboard_set(text_to_copy)

    elif event == '-SIGNATURE_COPY-':
        text_to_copy = values['-SIGNATURE-']
        sg.clipboard_set(text_to_copy)
    
    elif event == '-MH_PUBLIC_KEY_COPY-':
        text_to_copy = values['-MH_PUBLIC_KEY-']
        sg.clipboard_set(text_to_copy)

    elif event == '-IDEA_KEY_COPY-':
        text_to_copy = values['-IDEA_KEY-']
        sg.clipboard_set(text_to_copy)
    
    elif event == '-CIPHER_CLEAR-':
        window['-CIPHERTEXT-'].update('')
    
    elif event == '-PLAIN_CLEAR-':
        window['-PLAINTEXT-'].update('')

    elif event == "Export Encryption":
        iv_text = values["-DECRYPTION_IV-"]
        # Export ciphertext
        with open("Ciphertext.txt", "w") as f:
            f.write(ciphertext.encode("utf-8").hex())
        # Export the encrypted IDEA key, the encrypted IDEA key signature, and the IV
        with open("Merkle-Hellman-public-key.txt", "w") as f:
            f.write(str(hex(encrypted_IDEA_key)))
        with open("Enryption-signature.txt", "w") as f:
            f.write(str(ECDSA_signature.hex()))
        with open("Encryption-IV.txt", "w") as f:
            f.write(iv_text)

# Close the window
window.close()

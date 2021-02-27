import os, discum, pyAesCrypt, io, threading, time
from tkinter import *
from enc_lib import *

# Reads in existing private key or generates a new one and saves it to an encrypted file.
def get_priv_key():
	# encryption/decryption buffer size - 64K
	bufferSize = 64 * 1024
	if os.path.exists('privKey.enc'):
		with open('privKey.enc', 'rb') as f:
			# initialize ciphertext binary stream
			fCiph = io.BytesIO(f.read())
		# initialize decrypted binary stream
		fDec = io.BytesIO()
		# get ciphertext length
		ctlen = len(fCiph.getvalue())
		# go back to the start of the ciphertext stream
		fCiph.seek(0)
		# decrypt stream
		password = 'moose' #input('Enter Password: ')
		try:
			pyAesCrypt.decryptStream(fCiph, fDec, password, bufferSize, ctlen)
		except ValueError as e:
			print(e)
			quit()
		privKey = int(fDec.getvalue())
	else:
		fCiph = io.BytesIO()
		privKey = secrets.randbelow(curve.field.n)
		password = 'moose' #input('Enter password to store private key: ')
		pyAesCrypt.encryptStream(io.BytesIO(bytes(str(privKey),'utf-8')), fCiph, password, bufferSize)
		with open('privKey.enc','wb') as f:
			f.write(fCiph.getvalue())
	return privKey

def start_master():
	try:
		my_client.gateway.run(auto_reconnect=True)
		time.sleep(1)
	except:
		pass

def send_message():
	msg = messageVar.get()
	if ID == '':
		channelIDvar.set('Enter channel ID before sending a message')
		return
	if publicKeyVar2.get() != '':
		try:
			msg = (':ENC:'+encrypt_to_string(msg.encode(), uncompress_to_point(curve, publicKeyVar2.get()))) if len(publicKeyVar2.get()) > 10 else msg
			my_client.sendMessage(ID,msg)
		except:
			publicKeyVar2.set('Problem with key entry')
			return
	else: publicKeyVar2.set('Enter a public key before sending a message')
	messageVar.set('')

master = Tk()
# TK VARS
messageVar = StringVar()
publicKeyVar = StringVar()
publicKeyVar2 = StringVar()
channelIDvar = StringVar()


privKey = get_priv_key()
pubKey = privKey * curve.g
publicKey = compress_point(pubKey)

# encryp/decrypt example
# encmsg = encrypt_to_string(message.encode(), uncompress_to_point(curve, publicKey2))
# decrypt_from_string(msg, privKey)

print('success')
my_client = discum.Client(email="email", password="password", token=None, proxy_host=None, proxy_port=None, user_agent="chrome", log=False)


# retrieve message history example
# listt = my_client.getMessages(ID,num=4).json()
# for i in listt[::-1]:
#     print(i['content'])

# my_client.sendMessage(ID,"test")
messages=[]
@my_client.gateway.command
def helloworld(resp):
	global ID
	ID = channelIDvar.get()
	if resp.raw['t'] == 'MESSAGE_CREATE':
		if resp.raw['d']['channel_id'] == ID:
			userID = resp.raw['d']['author']['id']
			messages.append(resp.raw['d']['content'])
	time.sleep(0.1)
# UI ELEMENTS
messagesBlock = Text(master)
messageBox = Entry(master, textvariable=messageVar)
sendBtn = Button(master, text="Send", command=send_message)
idboxLabel = Label(master, text = '<- Your Channel ID')
publicKeyLabel = Label(master, text=" <- Your Public Key")
publicKeyLabel2 = Label(master, text=" <- Recipient Key")
idbox = Entry(master, textvariable=channelIDvar)
publicKeyBox = Entry(master, textvariable=publicKeyVar)
publicKeyBox2 = Entry(master, textvariable=publicKeyVar2)

# UI GRIDDING
idboxLabel.grid(row=0, column=2,sticky='w')
idbox.grid(row=0,column=0,columnspan=2, rowspan=1, sticky='ew')
publicKeyLabel.grid(row=1,column=2,sticky='w')
publicKeyBox.grid(row=1, column=0, columnspan=2, rowspan=1, sticky='ew')
publicKeyLabel2.grid(row=2,column=2,sticky='w')
publicKeyBox2.grid(row=2, column=0, columnspan=2, rowspan=1, sticky='ew')
messagesBlock.grid(row=3, column=0, columnspan=2, rowspan=4)
messageBox.grid(row=8, column=0, columnspan=2, sticky='ew')
sendBtn.grid(row=8, column=2, sticky='ew')

publicKeyVar.set(publicKey)

def updateChatbox():
	global data
	data = ""
	data += "\n".join([decrypt_from_string(msg[5:], privKey) if ':ENC:' in msg else msg for msg in messages])+"\n"
	messagesBlock.delete('1.0', END)
	messagesBlock.insert('1.0', data)
	master.after(100, updateChatbox)


master.after(100, updateChatbox)

master_thread = threading.Thread(target=start_master)
master_thread.start()
master.mainloop()
my_client.gateway.close()



# response structure example
# [92m< {'t': 'MESSAGE_CREATE',
#          's': 5, 
#          'op': 0, 
#          'd': {'type': 0, 'tts': False, 'timestamp': '2021-01-26T10:55:26+00:00', 'referenced_message': None, 'pinned': False, 'nonce': '803578842403831808', 'mentions': [], 'mention_roles': [], 'mention_everyone': False, 'id': '803578843234304021', 'flags': 0, 'embeds': [], 'edited_timestamp': None, 'content': 'and it is alright to become a conspiracy theorist for a game I think lol', 'channel_id': '803136870530678784', 'author': {'username': 'RyanG', 'public_flags': 0, 'id': '272094335556648961', 'discriminator': '9686', 'avatar': '55ff954e7c70d807eac4744db4935959'}, 'attachments': []}}

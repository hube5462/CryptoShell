import cmd
import os
from stat import *			#this library allows us to check file permissions
import getpass
from Crypto.Cipher import AES
from Crypto.Cipher import Blowfish
from passlib.hash import sha256_crypt
import shlex, subprocess, sys

user = os.getlogin()		#global variable user obtained using who ever is logged in
key = ""			#global variable key
cipher_text = ""		#global variable to hold cipher text
hash_file = "." + user + ".shadow"	#global shadow file to hold hashed key
flag = 0			#global variable for encryption type

class CryptoShell(cmd.Cmd):	#cryptoshell class

	print "********Welcome to CryptoShell********"		#welcome message
	print "********We encrypt by default*********"		#welcome message
	print
	
	
	if user == "root":				#if the user is root
		prompt = "root@CryptoShell:~#"		#roots prompt
	else:						#otherwise
		prompt = "%s@CryptoShell:~$" %user	#who ever the user is prompt
	
	def preloop(self):				#this function will be launched before the Cmd loop
		global hash_file			#we want to access the hash file name
		global flag

		if not os.path.isfile(hash_file):	#check to see if the file exists; if not, create a file
			CryptoShell.do_setkey(self)	#call setkey to set the key and save its hash in a hidden file
		
	def default(self, line):
		global user
		args = shlex.split(line)
		os.environ["USER"] = user
		os.environ["HOME"] = os.path.expanduser("~")

		if args[0]=='cd':
			try:
				if args[1][0] == "~":
					os.chdir(os.path.expanduser(args[1]))
				else:
					os.chdir(os.path.expandvars(args[1]))
			except:
				print "[*] %s: No such file or directory" %(args[1])		#check the value in args being passed
		else:
			try:
				if args[0]=='nano':
					CryptoShell.do_encrypt(self, line)
				elif args[0]=='rm' and args[1]=='.'+user+'.shadow':
					raise Exception("[*]%s: File immutable." %(args[1]))
				else:
					subprocess.call(args)
					
			except Exception as e:
				print e
				print "[*] %s: command not found" %(args[0])

	#at the present, setkey only gets called if there is no shadow file
	#the shadow file exists so that if the user launches the shell only to decrypt files, they can enter
	#their key and it can be hashed and compared to the hash in the shadow file;
	#only storing the key in a variable means that the user would always have to encrypt first (to enter in the
	#key); without entering in a key, going to decrypt first would compare an empty key variable with the user's
	#input throwing an error; another solution is found in designing the system to always require the user to 
	#enter in a key before any other activity can transpire

	def do_setkey(self):
		length = 16
		global key
		global hash_file
		hash = ""

		while len(key) != 16 and len(key) != 24 and len(key) !=32:
			key = getpass.getpass(prompt="Please enter a key of 16, 24, or 32 characters: " ) #prompt the user for a key
			if len(key) != 16 and 24 and 32:
				print "The keys length was: %i" %(len(key)) + "Please try again."		#if the key was not of proper length then inform the user
				continue
			hash = sha256_crypt.encrypt(key, salt="123")
			#print "If we typed a bad key, we shouldn't have gotten this far."
			
			if os.path.isfile(hash_file):
				file = open(hash_file, 'r')
				hashed_key = file.readline()
				file.close()					
				if hashed_key != hash:
					print "Warning: This is a different key.  Would you still like to proceed? Press y or n."
					answer = raw_input()
					if answer == "y":
						subprocess.call(['chmod', '0700', os.getcwd() + "/" + hash_file])
						file = open(hash_file, 'w')
						file.write(hash)
						file.close()
						break
					else:
						key = ""						
			else:
				file = open(hash_file, 'a+')
				file.write(hash)
				subprocess.call(['chmod', '0400', os.getcwd() + "/" + hash_file])
				file.close()
						#user wants to decrypt before encrypting, he
								#can enter his key and it gets hashed and compared
								#with the hash in the shadow file
		
		

	def do_encrypt(self, line):
		length = 16		#length intialized to 16 for the crypto libraries sake.
		text = ""		#text variable intialized
		global key		#use global variables key and cipher_text
		global cipher_text
		global flag
	

		if key == "":				#if the system does not have a user key, get it from the user
			CryptoShell.do_setkey(self)
		
		print "Please select AES (press a) or Blowfish (press b) cipher:"
		
		while True:
			enc_type = raw_input()
			if enc_type == 'b':
				flag = 1		#we are now using Blowfish encryption
				break			#get out of the infinite loop
			elif enc_type != 'a':
				print "[*]User Error: Please enter either a or b."	#the user can only enter a or b
			else:
				flag = 0		#we are now using AES encryption
				break			#get out of the infinite loop
		
		if flag == 0:
			Crypt_Obj = AES.new(key, AES.MODE_ECB)			#create an instance of out AES encryption object
		else:
			Crypt_Obj = Blowfish.new(key, Blowfish.MODE_ECB)

	
		args = shlex.split(line)
		
		if len(args) == 0 or len(args) == 1:
			print "Please enter the name of the file you would like work on: "
			file_name = raw_input()					#grab the file name from the user
		else:
			file_name = args[1]
		
		try:
			perm = '400'			#the octal code for user only read permission
			
			if flag == 1:
				if os.path.isfile(file_name + ".bf"):
					raise ValueError("[*]%s Warning: Encrypted blowfish file %s.bf already exists." %(file_name, file_name))
				elif os.path.isfile(file_name):
					nlength = len(file_name) - 3
					f_ext = file_name[nlength] + file_name [nlength + 1] + file_name[nlength + 2]
					if f_ext == ".bf":
						raise ValueError("[*]%s Warning: Encrypted File!" %(file_name))	#if it is user only read, throw exception					
					elif(perm == oct(os.stat(file_name)[ST_MODE])[-3:]):	#if it does, check for permissions
						raise ValueError("[*]%s Warning: Encrypted File!" %(file_name))	#if it is user only read, throw exception
			
			else:
				if(os.path.isfile(file_name)):
					if(perm == oct(os.stat(file_name)[ST_MODE])[-3:]):	#if it does, check for permissions
						raise ValueError("[*]%s Warning: Encrypted File!" %(file_name))	#if it is user only read, throw exception
			

			subprocess.call(['nano', file_name])	#otherwise, proceed as normal
			
			try:
				
				with open(file_name, 'a+') as file:		#open a new file if it doesn't exist, otherwise start writing at the end of the existing file
					text = file.read()					#the message variable holds the entire message
										
					while (len(text)%16 != 0):				#The crypto library is a little funky
						text +=	" "					#So while the length of text is not divisible by 16 then append a blank space
					cipher_text = Crypt_Obj.encrypt(text)		#we have text and we pass it to our crypto object and then store the vaule in cipher text.
					file = open(file_name, 'w')	
					file.write(cipher_text)
				if flag == 1:
					os.rename(file_name, file_name + ".bf")
					file_name = file_name + ".bf"	

				subprocess.call(['chmod', '0400', os.getcwd() + "/" + file_name])
					
			except IOError as e:					
				print "[*] %s: unable to open file." %(file_name)

		except ValueError as e:			#this statement will catch file permission errors
			print e
		
				
	def do_decrypt(self, line):	#to decrypt type decrypt
		
		plain_text = ""		#intialize a variable called plain text
		i = 0			#intialize counter i is intilized to 0
		global hash_file
		global key		#not using this right now, but I'm leaving it here in case you don't
					#like or want to modify the hash/shadow file scheme
		file_ext = ""
		
		file_name = raw_input("Please enter the file you would like to decrypt: ")	#get the name of the 
												#file to be decrypted
		
		key_check = str(getpass.getpass(prompt="To decrypt, please enter your key: "))			#prompt the user to enter their key
		hashed_key = sha256_crypt.encrypt(key_check, salt="123")	#hash user key input
		file = open(hash_file, 'r')				#open shadow file 
		hash = file.readline()					#retrieve stored hash key
		
		if hashed_key == hash:		#check the hash of the user input with the hash from the shadow file
			key = key_check
			try:
				perm = '700'		#octal permission for user read write and execute privileges

				if os.path.isfile(file_name):	#check to see if the file exists
					if (perm == oct(os.stat(file_name)[ST_MODE])[-3:]):
						raise ValueError("Warning: This file is already decrypted!")
				else:
					raise ValueError("[*]%s: File does not exist." %(file_name))

		
				
				try:
					fn_len = len(file_name)
					file_ext = file_name[fn_len - 3] + file_name[fn_len -2] + file_name[fn_len -1]
					
					if file_ext != ".bf":
						Crypt_Obj = AES.new(key_check, AES.MODE_ECB)	#if it checks, it's okay to use the plain
										#text key the user submitted (key_check)
					else:
						Crypt_Obj = Blowfish.new(key_check, Blowfish.MODE_ECB)
		

					with open(file_name, 'r') as file:
						cipher_text = file.read()	#get the cipher text from the file
				except IOError as e:
					#print "Unable to open file."		#if the file doesn't exist, inform the user			
					print e
				plain_text = Crypt_Obj.decrypt(cipher_text)	#to decrypt the cipher text and store the result in plain text
				subprocess.call(['chmod', '0700', os.getcwd() + "/" + file_name])
                        	file = open(file_name, 'w')
                        	file.write(plain_text + "\n")
				file.close()
				if file_ext == ".bf":
					new_file_name = ""
					new_length = len(file_name) - 3
					i = 0
					while i < new_length:
						new_file_name += file_name[i]
						i += 1

					os.rename(file_name, new_file_name)
				
			except ValueError as e:
				print e
		else:	
			while hashed_key != hash and i<2:							#while the key does not = keycheck and the attempts arent greater than 2
				key_check = getpass.getpass(prompt="[*] Your key was incorrect")		#prompt the user again letting them know that the key is not correct.
				hashed_key = sha256_crypt.encrypt(key_check, salt="123")

				if hashed_key == hash:
					key = key_check
					try:
						perm = '700'		#octal permission for user read write and execute privileges

						if os.path.isfile(file_name):	#check to see if the file exists
							if (perm == oct(os.stat(file_name)[ST_MODE])[-3:]):
								raise ValueError("Warning: This file is already decrypted!")
						else:
							raise ValueError("[*]%s: File does not exist." %(file_name))

		
				
						try:
							fn_len = len(file_name)
							file_ext = file_name[fn_len - 3] + file_name[fn_len -2] + file_name[fn_len -1]

							if file_ext != ".bf":
								Crypt_Obj = AES.new(key_check, AES.MODE_ECB)	#if it checks, it's okay to use the plain
										#text key the user submitted (key_check)
							else:
								Crypt_Obj = Blowfish.new(key_check, Blowfish.MODE_ECB)
		

							with open(file_name, 'r') as file:
								cipher_text = file.read()	#get the cipher text from the file
						except IOError as e:
							#print "Unable to open file."		#if the file doesn't exist, inform the user			
							print e
						plain_text = Crypt_Obj.decrypt(cipher_text)	#to decrypt the cipher text and store the result in plain text
						subprocess.call(['chmod', '0700', os.getcwd() + "/" + file_name])
                        			file = open(file_name, 'w')
                        			file.write(plain_text + "\n")
						file.close()

						if file_ext == ".bf":
							new_file_name = ""
							new_length = len(file_name) - 3
							i = 0
							while i < new_length:
								new_file_name += file_name[i]
								i += 1

							os.rename(file_name, new_file_name)
					except ValueError as e:
						print e

				else:							#otherwise...
					print"That is not your key..."
					print
					print"   @@@@@@@@@     "
					print"  @  @@@@@  @    "
					print"  @   @@@   @    "
					print"      @@@        "
					print"      @@@        "
					print"      @@@        " 
					print" @@@@@@@@@@@@@@@@@@@@@@@@@@@  @@     @@"
					print"@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ @@@@@@@@@"  
					print"@@@@@@@    @@   @@@   @@ @@@@@ @@@@@@@"
					print"@@x@@@@ @@@@  @  @@@ @@@ @@@@@@  @@@"
					print"@@@@ @@    @     @@@ @@@ @@@@@@@@@@@"
					print"    @@@ @@@@ @@@ @@@ @@@ @@@@@@@@@@@" 
					print"@@@@@@@ @@@@ @@@ @@   @@    @@@@@@@"
					print"@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
					print
					i += 1
		if i == 2:
			#CryptoShell.do_exit(self, line)	#why didn't this line work?	
								#if the user key failed more than three times, exit
			return True

		print plain_text #display the plaintext 

	def do_change_key(self, line):
		
		global key
		
		key_check = getpass.getpass(prompt="Please enter your current key before changing to a new one: ")	#prompt the user to enter their key
		if key == key_check:
			key = getpass.getpass(prompt="Please enter a key of 16, 24, or 32 characters: ")
			while len(key) != 16 and len(key) != 24 and len(key) !=32:
				key = getpass.getpass(prompt="Please enter a key of 16, 24, or 32 characters: ")
				if len(key) != 16 and 24 and 32:
					print "The keys length was: %i" %(len(key))
		else:
			print "[*] Your key was incorrect"
			print
	def help_encrypt(self):
		print "Enter your key and enter the message you want to encrypt"
	def help_decrypt(self):
		print "Enter your key and the message you want to decrypt"
	def help_exit(self):
		print "To exit CryptoShell type exit"


	def emptyline(self):
		pass		

	def do_exit(self, line):
		return True

if __name__=='__main__':
	CryptoShell().cmdloop()





#complete_your_function
#takes 4 args
#text-> is the string we are matching against, all returned matches must begin with it.
#line-> the current input line
#begidx->the begining index in the line of the text being matched.
#endidx is the end of the index in the line being matched.



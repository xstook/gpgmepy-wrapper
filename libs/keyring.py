# Original Author: Michael Santoro
# Original Date: November 10, 2025

# These are some wrapper functions on the gpg bindings for python
# If multithreaded it should be used within a lock

import sys
import os
try:
	import gpg
except:
	print("[ERROR] Could not 'import gpg', try")
	print("        export LD_LIBRARY_PATH=/usr/local/lib/")
	sys.exit(1)
from gpg.constants.sig.mode import CLEAR, DETACH
import gpg.gpgme as gpgme
from gpg.errors import GPGMEError, BadSignatures


# This class is not meant to be instantiated
# All methods should be called from the class, i.e. Keyring.initialize(""), Keyring.sign("")
class Keyring:
	home = ""
	fpr_lookup_secret = dict() # Key: key_name, Value: fpr
	fpr_lookup_public = dict() # Key: key_name, Value: fpr

	# This method needs to be called first before using the other methods
	@classmethod
	def initialize(cls, home):
		cls.home = os.path.join(home, "wiregram.keyring")
		os.makedirs(cls.home, exist_ok=True)
		cls.populate_fpr_lookups()


	# Returns the fpr (fingerprint) of the specified key_name
	# @param key_name The name of the key
	# @param secret True includes users with private keys, False is users with only public keys
	#               Note that all private keys include a public key
	# @return The fpr for the key_name if found, otherwise an empty string ""
	@classmethod
	def get_fpr(cls, key_name, secret=False):
		if secret:
			if key_name in cls.fpr_lookup_secret:
				return cls.fpr_lookup_secret[key_name]
			else:
				return ""

		else:
			if key_name in cls.fpr_lookup_public:
				return cls.fpr_lookup_public[key_name]
			else:
				return ""


	# Determines if a key_name exists in the keyring
	@classmethod
	def is_registered(cls, key_name, secret=False):
		return cls.get_fpr(key_name, secret=secret) != ""


	# @return A dictionary of key_name to fpr. { key_name: fpr }
	@classmethod
	def populate_fpr_lookups(cls):
		cls.fpr_lookup_secret.clear()
		cls.fpr_lookup_public.clear()

		# Populate secret keys
		with gpg.Context(armor=True, home_dir=cls.home) as c:
			keys = list(c.keylist(secret=True))
			for key in keys:
				fpr = key.fpr
				key_name = key.uids[0].uid
				cls.fpr_lookup_secret[key_name] = fpr

		# Populate public keys
		with gpg.Context(armor=True, home_dir=cls.home) as c:
			keys = list(c.keylist(secret=False))
			for key in keys:
				fpr = key.fpr
				key_name = key.uids[0].uid
				cls.fpr_lookup_public[key_name] = fpr




	# Signs the message with the specified key's private key
	# Clearsign mode embeds the signature with the message
	# Detached mode creates a standalone signature
	# @param clearsign True for mode.CLEAR, False for mode.DETACH
	# @return if DETACH the signature is returned
	#         if CLEAR the signed message is returned
	@classmethod
	def sign(cls, message, key_name, clearsign=True):
		mode = CLEAR if clearsign else DETACH
		with gpg.Context(armor=True, home_dir=cls.home) as c:
			fpr = cls.get_fpr(key_name, secret=True)
			keys = list(c.keylist(pattern=fpr, secret=True))
			if len(keys) != 1:
				return ""
			c.signers = keys
			(signed, result) = c.sign(message.encode("utf-8"), mode=mode)
			return signed.decode("utf-8")


	# Verifies either a clearsign message with embedded signature, or plaintext message with detached signature
	# Uses the embedded key name if present in signature for verification, otherwise tries all keys in Keyring
	# @param message The message to verify, can either be embedded clearsign of plaintext for detached
	# @param signature None for a clearsign message, otherwise --armor signature for detached
	# @return (result, plaintext) Tuple with the first element being a True/False indicating verification status
	#                             The second element is the original plaintext message
	@classmethod
	def verify(cls, message, signature=None):
		if signature != None:
			signature = signature.encode("utf-8")

		with gpg.Context(armor=True, home_dir=cls.home) as c:
			try:
				(plaintext, result) = c.verify(message.encode("utf-8"), signature=signature)

				# plaintext is None for valid detached signatures
				if plaintext == None:
					plaintext = message
				else:
					plaintext = plaintext.decode("utf-8")

				return (plaintext, True)

			except BadSignatures as e:
				# If clearsign
				if signature == None:
					plaintext = e.results[0].decode("utf-8")
					return (plaintext, False)

				# If detached
				else:
					return(message, False)

			except GPGMEError as e:
				return (message, False)
	

	@classmethod
	def encrypt(cls, message, key_name):
		with gpg.Context(armor=True, home_dir=cls.home) as c:
			fpr = cls.get_fpr(key_name)
			keys = list(c.keylist(pattern=fpr, secret=False))
			if len(keys) != 1:
				return ""
			try:
				(message_encrypted, result, signature_result) = c.encrypt(message.encode("utf-8"), recipients=keys, always_trust=True)
			except:
				return ""

		return message_encrypted.decode("utf-8")
	
	
	@classmethod
	def decrypt(cls, ciphertext, key_name):
		with gpg.Context(armor=True, home_dir=cls.home) as c:
			try:
				(message, result, verify_result) = c.decrypt(ciphertext.encode("utf-8"))
			except:
				return "[ERROR] Could not decrypt"

		return message.decode("utf-8")
	
	
	# Creates a new keypair, public and private keys, with the specified key name
	# @param key_name The name of the key
	# @return A GenkeyResult object, can be used to get the fpr, i.e. create_key("").fpr
	@classmethod
	def create_key(cls, key_name):
		with gpg.Context(armor=True, home_dir=cls.home) as c:
			try:
				genkey_result = c.create_key(key_name, algorithm="rsa4096", expires=False, sign=True, encrypt=True, certify=True, authenticate=True)
			except:
				return None
			cls.fpr_lookup_secret[key_name] = genkey_result.fpr
			cls.fpr_lookup_public[key_name] = genkey_result.fpr
			return genkey_result


	# Removes a key from the Keyring, both public and private keys will be removed
	# If the key_name pattern matches more than one key, none will be removed
	# @param key_name The name of the key
	# @return True if key removed, False if no key removed
	@classmethod
	def remove_key(cls, key_name):
		with gpg.Context(armor=True, home_dir=cls.home) as c:
			fpr = cls.get_fpr(key_name)
			keys = list(c.keylist(pattern=fpr, secret=False))
			if len(keys) != 1:
				return False
			try:
				c.op_delete_ext(keys[0], gpgme.GPGME_DELETE_ALLOW_SECRET | gpgme.GPGME_DELETE_FORCE)
			except:
				return False

		if key_name in cls.fpr_lookup_secret:
			del cls.fpr_lookup_secret[key_name]
		if key_name in cls.fpr_lookup_public:
			del cls.fpr_lookup_public[key_name]
		return True


	# @param key_name The name of the key
	# @param secret Specify if the pubkey or privkey should be returned
	# @return The pubkey or privkey in readable --armor form
	@classmethod
	def export_key(cls, key_name, secret=False):
		with gpg.Context(armor=True, home_dir=cls.home) as c:
			fpr = cls.get_fpr(key_name, secret=secret)
			try:
				if secret:
					result = c.key_export_secret(pattern=fpr).decode("utf-8")
				else:
					result = c.key_export(pattern=fpr).decode("utf-8")
			except:
				result = ""

			return result if result != None else ""


	# @param key A string of the gpg key exported as --armor, it will use the key_name embedded from when the key was created
	@classmethod
	def import_key(cls, key):
		with gpg.Context(armor=True, home_dir=cls.home) as c:
			result = c.key_import(data=key.encode("utf-8"))
			#imported = True if result.imported == 1 else False
			#secret = True if result.secret_imported == 1 else False
			cls.populate_fpr_lookups()
			return result


	# @param key A key object, it will use the key_name embedded from when the key was created
	@classmethod
	def import_key_object(cls, key):
		with gpg.Context(armor=True, home_dir=cls.home) as c:
			result = c.op_import_keys([key])
			cls.populate_fpr_lookups()
			return result


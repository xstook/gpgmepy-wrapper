#!/usr/bin/python3

from libs.keyring import Keyring

HOME = "wiregram-data-test"

Keyring.initialize(HOME)


# Create
print("Create key: {}".format(Keyring.create_key("frank").fpr))

# Sign
signed = Keyring.sign("all your base", "frank")

# Verify
(message, verify_result) = Keyring.verify(signed)
print("Verify signature: {}".format(verify_result))

# Encrypt
ciphertext = Keyring.encrypt("all your base", "frank")

# Decrypt
plaintext = Keyring.decrypt(ciphertext, "frank")
print("Decrypted message: {}".format(plaintext == "all your base"))

# Export
privkey = Keyring.export_key("frank", secret=True)
pubkey = Keyring.export_key("frank")

# Remove
print("Remove key: {}".format(Keyring.remove_key("frank")))

# Import privkey
print("Import key: {}".format(Keyring.import_key(privkey).secret_imported == 1))

# Remove
print("Remove key: {}".format(Keyring.remove_key("frank")))

# Import pubkey
print("Import key: {}".format(Keyring.import_key(pubkey).imported == 1))

# Remove
print("Remove key: {}".format(Keyring.remove_key("frank")))





# Display All
#print("")
#print("")
#print("===========")
#print("ALL PRIVATE")
#print("===========")
#for key_name in Keyring.fpr_lookup_secret:
#	fpr = all_private_users[key_name]
#	print("{}: {}".format(key_name, fpr))
#
#print("")
#print("==========")
#print("ALL PUBLIC")
#print("==========")
#for key_name in Keyring.fpr_lookup_public:
#	fpr = all_public_users[key_name]
#	print("{}: {}".format(key_name, fpr))


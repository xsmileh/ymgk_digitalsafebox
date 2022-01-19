from Cryptodome.PublicKey import RSA
from Cryptodome import Random
from Cryptodome.Cipher import PKCS1_OAEP


def rsa_encrypt_decrypt(userfilepass):
    key = RSA.generate(1024)
    private_key = key.exportKey('PEM')

    public_key = key.publickey().exportKey('PEM')
    encrypted_pass = str.encode(userfilepass)


    rsa_public_key = RSA.importKey(public_key)
    rsa_public_key = PKCS1_OAEP.new(rsa_public_key)
    encrypted_pass = rsa_public_key.encrypt(encrypted_pass)

    # sendEmail.sendMail("RSAFILEKEY",private_key)

    return encrypted_pass


    #encrypted_text = b64encode(encrypted_text)
    # # print('your encrypted_text is : {}'.format(encrypted_text))



def rsa_decrypt(encrypted_text,userfilepass,private_key):

    rsa_private_key = RSA.importKey(private_key,userfilepass)
    rsa_private_key = PKCS1_OAEP.new(rsa_private_key)
    decrypted_text = rsa_private_key.decrypt(encrypted_text)


    return decrypted_text



    # rsa_private_key = RSA.importKey(private_key,asd)
    # rsa_private_key = PKCS1_OAEP.new(rsa_private_key)
    # decrypted_text = rsa_private_key.decrypt(encrypted_text)

    # # print('your decrypted_text is : {}'.format(decrypted_text))
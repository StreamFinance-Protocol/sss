1 - On local device run the following command to generate your private key

openssl genrsa -out private.pem 2048

2 - On your local device generate the corresponding public key

openssl rsa -in private.pem -outform PEM -pubout -out public.pem

3 - place public keys in the public_keys folder on the EC2

4 - compile the code

gcc setup.c -o setup randombytes.o sss.o hazmat.o tweetnacl.o -I/opt/homebrew/opt/openssl/include -L/opt/homebrew/opt/openssl/lib -lssl -lcrypto 

5 - run the code

./gen_shards.sh

6 - copy encrypted shares files and paste it on your personal device

7 - compile the code to decrypt the share

gcc decrypt.c -o decrypt randombytes.o sss.o hazmat.o tweetnacl.o -I/opt/homebrew/opt/openssl/include -L/opt/homebrew/opt/openssl/lib -lssl -lcrypto

8 - decrypt the share 

./decrypt shares/solal.txt private_keys/private_solal.pem

9 - store the share and delete your private key

10 - To combine shares we first compile the combine function 

gcc combine.c -o combine sss.o randombytes.o hazmat.o tweetnacl.o -I/opt/homebrew/opt/openssl/include -L/opt/homebrew/opt/openssl/lib -lssl -lcrypto

11 - combine the shares 

./combine <shard1> <shard2> <shard3>



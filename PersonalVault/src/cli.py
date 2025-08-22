import argparse, sys, os
from vault import generate_keypair, load_private_key, encrypt_file, decrypt_file

def main():
    parser = argparse.ArgumentParser(description="PersonalVault")
    sub = parser.add_subparsers(dest='cmd')
    sub.add_parser('init')
    sub.add_parser('lock').add_argument('file')
    sub.add_parser('unlock').add_argument('file')
    args = parser.parse_args()

    if args.cmd == 'init':
        pw = input("Set vault passphrase: ")
        generate_keypair(pw)
        print("Vault keypair created.")
    elif args.cmd == 'lock':
        pub = load_private_key(input("Passphrase: ")).public_key()
        encrypt_file(args.file, pub)
    elif args.cmd == 'unlock':
        prv = load_private_key(input("Passphrase: "))
        decrypt_file(args.file, prv)
    else:
        parser.print_help()

if __name__ == '__main__':
    main()

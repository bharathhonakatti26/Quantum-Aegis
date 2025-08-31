import argparse
import base64
import json
from pathlib import Path

from key_exchange import KyberKeyExchange
from signature import DilithiumSignature
from encryption import AES256GCM

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from typing import Optional


def b64_encode(b: bytes) -> str:
    return base64.b64encode(b).decode('ascii')


def b64_decode(s: str) -> bytes:
    return base64.b64decode(s)


def write_binary_b64(path: Path, data: bytes):
    path.write_text(b64_encode(data))


def read_binary_b64(path: Path) -> bytes:
    txt = path.read_text()
    try:
        return b64_decode(txt)
    except Exception:
        # fallback: file may be raw binary
        return path.read_bytes()


def derive_aes_key(shared_secret: bytes, info: bytes = b'quantum-aegis') -> bytes:
    hkdf = HKDF(length=32, salt=None, info=info, algorithm=hashes.SHA3_256())
    return hkdf.derive(shared_secret)


def resolve_encrypted_path(name: str) -> Path:
    p = Path(name)
    if p.exists():
        return p
    enc_dir = Path('Encrypted')
    cand = enc_dir / name
    if cand.exists():
        return cand
    # try with .enc suffix
    cand2 = enc_dir / (name if name.endswith('.enc') else (name + '.enc'))
    if cand2.exists():
        return cand2
    # last resort: return original Path (will error later)
    return p


def safe_input(prompt: str, default: Optional[str] = None) -> Optional[str]:
    """Prompt wrapper that returns None on KeyboardInterrupt/EOFError.

    If default is provided and the user enters an empty line, returns default.
    """
    try:
        res = input(prompt)
    except (KeyboardInterrupt, EOFError):
        print('\nInterrupted by user')
        return None
    if res == '' and default is not None:
        return default
    return res


def cmd_gen_keys(args):
    # KEM keys
    kem = KyberKeyExchange()
    pub, priv = kem.generate_keypair()
    keys_dir = Path('Keys')
    keys_dir.mkdir(parents=True, exist_ok=True)
    pub_path = keys_dir / (args.out_prefix + '.kem.pub')
    priv_path = keys_dir / (args.out_prefix + '.kem.priv')
    write_binary_b64(pub_path, pub)
    write_binary_b64(priv_path, priv if priv is not None else b'')
    print(f'Wrote KEM public -> {pub_path}, private -> {priv_path}')

    # Signature keys (optional)
    if args.generate_sig:
        sig = DilithiumSignature()
        spub, spriv = sig.generate_keypair()
    spub_path = keys_dir / (args.out_prefix + '.sig.pub')
    spriv_path = keys_dir / (args.out_prefix + '.sig.priv')
    write_binary_b64(spub_path, spub)
    write_binary_b64(spriv_path, spriv if spriv is not None else b'')
    print(f'Wrote SIG public -> {spub_path}, private -> {spriv_path}')


def cmd_encrypt(args):
    recipient_pub = read_binary_b64(Path(args.recipient_pub))
    message = Path(args.infile).read_bytes() if args.infile else args.message.encode()

    kem = KyberKeyExchange()
    encapsulated, shared = kem.encapsulate(recipient_pub)
    if shared is None:
        raise RuntimeError('KEM did not return a shared secret')

    aes_key = derive_aes_key(shared, info=args.info.encode() if args.info else b'quantum-aegis')
    aes = AES256GCM(aes_key)
    nonce, ciphertext = aes.encrypt(message)

    envelope = {
        'alg': f'{kem.mechanism}+AES-256-GCM',
        'encapsulated_key': b64_encode(encapsulated),
        'nonce': b64_encode(nonce),
        'ciphertext': b64_encode(ciphertext),
        'info': args.info or '',
    }

    # optional signing
    if args.sign_with:
        signer = DilithiumSignature()
        signer_pub = read_binary_b64(Path(args.sign_with + '.sig.pub')) if Path(args.sign_with + '.sig.pub').exists() else None
        signer_priv = read_binary_b64(Path(args.sign_with + '.sig.priv'))
        signer.public_key = signer_pub
        signer.private_key = signer_priv
        signature = signer.sign(ciphertext)
        envelope['signature'] = b64_encode(signature)
        if signer_pub:
            envelope['signer_pub'] = b64_encode(signer_pub)

    out_path = Path(args.outfile)
    # Place envelopes in Encrypted/ directory for organization
    if out_path.parent == Path('.') or out_path.parent == Path(''):
        enc_dir = Path('Encrypted')
        enc_dir.mkdir(parents=True, exist_ok=True)
        out_path = enc_dir / out_path
    else:
        out_path.parent.mkdir(parents=True, exist_ok=True)

    out_path.write_text(json.dumps(envelope))
    print(f'Encrypted message -> {out_path}')


def cmd_decrypt(args):
    in_path = resolve_encrypted_path(args.infile)
    env = json.loads(in_path.read_text())
    encapsulated = b64_decode(env['encapsulated_key'])
    nonce = b64_decode(env['nonce'])
    ciphertext = b64_decode(env['ciphertext'])
    info = env.get('info', '')

    # load private key
    priv = read_binary_b64(Path(args.priv))
    kem = KyberKeyExchange()
    kem.private_key = priv
    shared = kem.decapsulate(encapsulated)
    aes_key = derive_aes_key(shared, info=info.encode() if isinstance(info, str) else info)
    aes = AES256GCM(aes_key)
    plaintext = aes.decrypt(nonce, ciphertext)

    # optional signature verification
    if 'signature' in env:
        signature = b64_decode(env['signature'])
        signer_pub = b64_decode(env['signer_pub']) if 'signer_pub' in env else None
        if signer_pub is None:
            print('Warning: signature present but no signer public key provided in envelope')
        else:
            verifier = DilithiumSignature()
            ok = verifier.verify(ciphertext, signature, signer_pub)
            print(f'Signature valid: {ok}')

    out_path = Path(args.outfile) if args.outfile else None
    if out_path:
        # write decrypted plaintexts to Decrypted/ by default
        if out_path.parent == Path('.') or out_path.parent == Path(''):
            dec_dir = Path('Decrypted')
            dec_dir.mkdir(parents=True, exist_ok=True)
            out_path = dec_dir / out_path
        else:
            out_path.parent.mkdir(parents=True, exist_ok=True)

        out_path.write_bytes(plaintext)
        print(f'Decrypted plaintext -> {out_path}')
    else:
        print(plaintext.decode())


def main():
    p = argparse.ArgumentParser(prog='qaegis')
    sub = p.add_subparsers(dest='cmd')

    g = sub.add_parser('gen-keys')
    g.add_argument('--out-prefix', required=True)
    g.add_argument('--generate-sig', action='store_true')
    g.set_defaults(func=cmd_gen_keys)

    e = sub.add_parser('encrypt')
    e.add_argument('--recipient-pub', required=True)
    e.add_argument('--infile', required=False)
    e.add_argument('--message', required=False, default='')
    e.add_argument('--outfile', required=True)
    e.add_argument('--info', required=False, default='')
    e.add_argument('--sign-with', required=False, help='key prefix used to sign (prefix.sig.priv/.pub)')
    e.set_defaults(func=cmd_encrypt)

    d = sub.add_parser('decrypt')
    d.add_argument('--priv', required=True)
    d.add_argument('--infile', required=True)
    d.add_argument('--outfile', required=False)
    d.set_defaults(func=cmd_decrypt)

    args = p.parse_args()
    if not hasattr(args, 'func'):
        # run interactive mode when no subcommand provided
        try:
            interactive_mode()
        except (KeyboardInterrupt, EOFError):
            print('\nInterrupted by user')
        return

    # Call chosen subcommand and handle Ctrl-C cleanly
    try:
        args.func(args)
    except (KeyboardInterrupt, EOFError):
        print('\nInterrupted by user')
        return


def interactive_mode():
    print('Interactive Quantum Aegis CLI (single-user mode)')
    print('This session will generate one KEM (Kyber) keypair and one Dilithium keypair and use them for all operations.')
    choice = safe_input('Generate new keys now? (Y/n): ')
    if choice is None:
        return
    choice = choice.strip().lower() or 'y'
    if choice == 'n':
        print('Aborting interactive session.')
        return

    # generate KEM and signature keys and keep in memory
    kem = KyberKeyExchange()
    kem_pub, kem_priv = kem.generate_keypair()
    kem.public_key = kem_pub
    kem.private_key = kem_priv

    sig = DilithiumSignature()
    sig_pub, sig_priv = sig.generate_keypair()
    sig.public_key = sig_pub
    sig.private_key = sig_priv

    print('Generated KEM and Dilithium keypairs.')
    save_choice = safe_input('Save keys to disk? (y/N): ')
    if save_choice is None:
        return
    save_choice = save_choice.strip().lower() or 'n'
    if save_choice == 'y':
        prefix = safe_input('Enter filename prefix (e.g. alice): ', default='key')
        if prefix is None:
            return
        prefix = prefix.strip() or 'key'
        keys_dir = Path('Keys')
        keys_dir.mkdir(parents=True, exist_ok=True)
        kem_pub_path = keys_dir / (prefix + '.kem.pub')
        kem_priv_path = keys_dir / (prefix + '.kem.priv')
        sig_pub_path = keys_dir / (prefix + '.sig.pub')
        sig_priv_path = keys_dir / (prefix + '.sig.priv')

        # overwrite existing files without prompting
        write_binary_b64(kem_pub_path, kem_pub)
        write_binary_b64(kem_priv_path, kem_priv if kem_priv is not None else b'')
        write_binary_b64(sig_pub_path, sig_pub)
        write_binary_b64(sig_priv_path, sig_priv if sig_priv is not None else b'')

        print('Created key files:')
        print(f'  {kem_pub_path.resolve()}')
        print(f'  {kem_priv_path.resolve()}')
        print(f'  {sig_pub_path.resolve()}')
    print(f'  {sig_priv_path.resolve()}')

    # set local variables for flows
    kem_pub = kem_pub
    kem_priv = kem_priv
    sig_pub = sig_pub
    sig_priv = sig_priv

    while True:
        print('\nChoose an action:')
        print('  1) Encrypt')
        print('  2) Decrypt')
        print('  3) Exit')
        choice = safe_input('Select 1/2/3: ')
        if choice is None:
            print('Interrupted; exiting interactive session')
            break
        choice = choice.strip()
        if choice == '1':
            # Encrypt flow
            recipient = safe_input('Recipient public key file (press Enter to use your generated KEM public): ', default='')
            if recipient is None:
                print('Interrupted; aborting this operation')
                continue
            recipient = recipient.strip()
            if recipient:
                recipient_pub = read_binary_b64(Path(recipient))
            else:
                recipient_pub = kem_pub

            msg_src = safe_input('Enter message text, or prefix with @ to read from file (e.g. @message.txt): ', default='')
            if msg_src is None:
                print('Interrupted; aborting this operation')
                continue
            msg_src = msg_src.strip()
            if msg_src.startswith('@'):
                infile = msg_src[1:]
                message = Path(infile).read_bytes()
            else:
                message = msg_src.encode()

            info = safe_input('Optional context/info (used in HKDF): ', default='')
            if info is None:
                print('Interrupted; aborting this operation')
                continue
            info = info.strip()
            kem = KyberKeyExchange()
            encapsulated, shared = kem.encapsulate(recipient_pub)
            if shared is None:
                print('KEM did not return shared secret; aborting')
                continue
            aes_key = derive_aes_key(shared, info=info.encode() if info else b'quantum-aegis')
            aes = AES256GCM(aes_key)
            nonce, ciphertext = aes.encrypt(message)
            envelope = {
                'alg': f'{kem.mechanism}+AES-256-GCM',
                'encapsulated_key': b64_encode(encapsulated),
                'nonce': b64_encode(nonce),
                'ciphertext': b64_encode(ciphertext),
                'info': info or '',
            }
            # always sign with generated Dilithium private key
            signer = DilithiumSignature()
            signer.private_key = sig_priv
            signature = signer.sign(ciphertext)
            envelope['signature'] = b64_encode(signature)
            envelope['signer_pub'] = b64_encode(sig_pub)

            outfile = safe_input('Output filename for envelope (e.g. out.enc): ', default='')
            if outfile is None:
                print('Interrupted; aborting')
                continue
            outfile = outfile.strip()
            if not outfile:
                print('No output filename provided; aborting')
                continue
            out_path = Path(outfile)
            if out_path.parent == Path('.') or out_path.parent == Path(''):
                enc_dir = Path('Encrypted')
                enc_dir.mkdir(parents=True, exist_ok=True)
                out_path = enc_dir / out_path
            else:
                out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(json.dumps(envelope))
            print(f'Encrypted message written to {out_path}')

        elif choice == '2':
            # Decrypt flow
            infile = safe_input('Path to envelope file to decrypt (filename or Encrypted/<file>): ', default='')
            if infile is None:
                print('Interrupted; aborting')
                continue
            infile = infile.strip()
            if not infile:
                print('No input file provided')
                continue
            in_path = resolve_encrypted_path(infile)
            if not in_path.exists():
                print(f'Envelope not found: {infile} (tried {in_path})')
                continue
            env = json.loads(in_path.read_text())
            encapsulated = b64_decode(env['encapsulated_key'])
            nonce = b64_decode(env['nonce'])
            ciphertext = b64_decode(env['ciphertext'])
            info = env.get('info', '')

            if kem_priv is None:
                print('No KEM private key available; cannot decrypt')
                continue
            kem = KyberKeyExchange()
            kem.private_key = kem_priv
            try:
                shared = kem.decapsulate(encapsulated)
            except Exception as e:
                print(f'decapsulate failed: {e}')
                continue
            aes_key = derive_aes_key(shared, info=info.encode() if isinstance(info, str) else info)
            aes = AES256GCM(aes_key)
            try:
                plaintext = aes.decrypt(nonce, ciphertext)
            except Exception as e:
                print(f'Decryption failed: {e}')
                continue

            # verify signature if present
            if 'signature' in env:
                signature = b64_decode(env['signature'])
                signer_pub = b64_decode(env['signer_pub']) if 'signer_pub' in env else sig_pub
                if signer_pub is None:
                    print('Signature present but no signer public key available to verify')
                else:
                    verifier = DilithiumSignature()
                    ok = verifier.verify(ciphertext, signature, signer_pub)
                    print(f'Signature valid: {ok}')

            out = safe_input('Output file to write plaintext (leave empty to print): ', default='')
            if out is None:
                print('Interrupted; aborting')
                continue
            out = out.strip()
            if out:
                out_path = Path(out)
                if out_path.parent == Path('.') or out_path.parent == Path(''):
                    dec_dir = Path('Decrypted')
                    dec_dir.mkdir(parents=True, exist_ok=True)
                    out_path = dec_dir / out_path
                else:
                    out_path.parent.mkdir(parents=True, exist_ok=True)
                out_path.write_bytes(plaintext)
                print(f'Plaintext written to {out_path}')
            else:
                print('\n----- PLAINTEXT -----')
                try:
                    print(plaintext.decode())
                except Exception:
                    print(plaintext)

        elif choice == '3':
            print('Exiting')
            break
        else:
            print('Unknown choice')


if __name__ == '__main__':
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print('\nInterrupted by user')
        # ensure clean exit code
        try:
            import sys

            sys.exit(1)
        except Exception:
            pass

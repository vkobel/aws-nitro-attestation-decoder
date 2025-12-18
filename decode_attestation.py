#!/usr/bin/env python3

import json
import base64
import cbor2
import argparse
from datetime import datetime, timezone
from pprint import pprint
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

# Algorithm constants
ES384_ALGORITHM_ID = -35
ES384_SIGNATURE_LENGTH = 96
ES384_R_S_LENGTH = 48

# Display constants
SEPARATOR_WIDTH = 60

def read_attestation_file(filepath):
    """Read attestation from JSON or raw base64 file

    Supports two formats:
    1. JSON: {"attestationDocument": "base64..."}
    2. Raw: base64 string directly
    """
    with open(filepath, 'r') as f:
        content = f.read().strip()

    # Try JSON format first
    try:
        data = json.loads(content)
        if 'attestationDocument' in data:
            return data['attestationDocument']
    except json.JSONDecodeError:
        pass

    # Assume raw base64
    return content

def decode_attestation(attestation_file):
    """Decode AWS Nitro attestation document"""

    # Read the attestation file (supports JSON or raw base64)
    attestation_b64 = read_attestation_file(attestation_file)

    # Base64 decode
    attestation_cbor = base64.b64decode(attestation_b64)

    # CBOR decode - this gives us a COSE Sign1 structure [protected, unprotected, payload, signature]
    cose_sign1 = cbor2.loads(attestation_cbor)

    # Extract the components
    if isinstance(cose_sign1, list) and len(cose_sign1) == 4:
        protected_headers_bytes = cose_sign1[0]
        unprotected_headers = cose_sign1[1]
        payload = cose_sign1[2]  # This is the actual attestation document (still CBOR encoded)
        signature = cose_sign1[3]

        # Decode the payload (which is also CBOR encoded)
        attestation_doc = cbor2.loads(payload)

        # Return both the COSE structure and the decoded document
        return {
            'cose': {
                'protected_headers': cbor2.loads(protected_headers_bytes) if isinstance(protected_headers_bytes, bytes) else protected_headers_bytes,
                'protected_headers_bytes': protected_headers_bytes,  # Keep raw bytes for verification
                'unprotected_headers': unprotected_headers,
                'signature': signature
            },
            'payload_bytes': payload,  # Keep raw payload bytes for verification
            'document': attestation_doc
        }
    else:
        # If it's not a COSE structure, just return as-is
        return cose_sign1

def format_value(value, key=None):
    """Recursively format values for readable output"""
    if isinstance(value, bytes):
        # For bytes, handle specially based on context
        if key == 'user_data':
            try:
                return {
                    'hex': value.hex(),
                    'decoded': value.decode('utf-8')
                }
            except UnicodeDecodeError:
                return f"<{len(value)} bytes, hex: {value.hex()[:100]}...>"
        elif key in ['certificate', 'public_key'] or (isinstance(key, str) and 'cert' in key.lower()):
            return f"<{len(value)} bytes>"
        else:
            # For small byte arrays, show hex
            if len(value) <= 64:
                return value.hex()
            else:
                return f"<{len(value)} bytes, hex: {value.hex()[:100]}...>"
    elif isinstance(value, dict):
        return {k: format_value(v, k) for k, v in value.items()}
    elif isinstance(value, list):
        return [format_value(v) for v in value]
    else:
        return value

def format_attestation(doc):
    """Format attestation document for readable output"""
    return format_value(doc)

def is_zero_filled(value):
    """Check if a value is zero-filled"""
    if isinstance(value, str):
        return value == '0' * len(value)
    elif isinstance(value, bytes):
        return value == b'\x00' * len(value)
    return False

def filter_nonzero_pcrs(pcrs):
    """Filter out zero-filled PCR values and return with indices"""
    if isinstance(pcrs, dict):
        return {k: v for k, v in pcrs.items() if not is_zero_filled(v)}
    elif isinstance(pcrs, list):
        return [(i, pcr) for i, pcr in enumerate(pcrs) if pcr and not is_zero_filled(pcr)]
    return []

def format_datetime(dt):
    """Format datetime for display"""
    return dt.strftime('%Y-%m-%d %H:%M:%S UTC')

def get_certificate_info(cert_der):
    """Extract certificate information including expiry dates"""
    cert = x509.load_der_x509_certificate(cert_der, default_backend())

    # Get validity dates
    not_before = cert.not_valid_before_utc
    not_after = cert.not_valid_after_utc
    now = datetime.now(timezone.utc)

    # Calculate days until expiry
    days_until_expiry = (not_after - now).days

    # Determine status
    if now < not_before:
        status = "⚠️  NOT YET VALID"
        status_detail = f"Valid from {format_datetime(not_before)}"
    elif now > not_after:
        status = "✗ EXPIRED"
        status_detail = f"Expired {abs(days_until_expiry)} days ago"
    elif days_until_expiry < 30:
        status = "⚠️  EXPIRING SOON"
        status_detail = f"Expires in {days_until_expiry} days"
    else:
        status = "✓ VALID"
        status_detail = f"Expires in {days_until_expiry} days"

    # Extract CN from subject and issuer for display
    subject_cn = None
    issuer_cn = None

    for attr in cert.subject:
        if attr.oid == x509.oid.NameOID.COMMON_NAME:
            subject_cn = attr.value
            break

    for attr in cert.issuer:
        if attr.oid == x509.oid.NameOID.COMMON_NAME:
            issuer_cn = attr.value
            break

    return {
        'cert': cert,
        'not_before': not_before,
        'not_after': not_after,
        'days_until_expiry': days_until_expiry,
        'status': status,
        'status_detail': status_detail,
        'subject': cert.subject.rfc4514_string(),
        'subject_cn': subject_cn,
        'issuer': cert.issuer.rfc4514_string(),
        'issuer_cn': issuer_cn,
        'is_self_signed': cert.subject == cert.issuer
    }

def verify_certificate_chain(cert_chain, root_cert_pem):
    """Verify the certificate chain up to the root certificate

    AWS Nitro chain structure:
    cert_chain[0] = enclave certificate
    cert_chain[1:] = CA bundle in reverse order (leaf to root)
      cert_chain[-1] = parent of enclave cert
      cert_chain[-2] = parent of cert_chain[-1]
      etc.
    """
    try:
        # Load root certificate
        root_cert = x509.load_pem_x509_certificate(root_cert_pem.encode(), default_backend())

        # Parse all certificates in the chain
        certs = []
        for cert_der in cert_chain:
            cert = x509.load_der_x509_certificate(cert_der, default_backend())
            certs.append(cert)

        if len(certs) < 2:
            return False, "Certificate chain too short"

        # Verify enclave cert (certs[0]) is signed by the last cert in cabundle (certs[-1])
        try:
            certs[-1].public_key().verify(
                certs[0].signature,
                certs[0].tbs_certificate_bytes,
                ec.ECDSA(certs[0].signature_hash_algorithm)
            )
        except InvalidSignature:
            return False, "Enclave certificate signature verification failed"

        # Verify the cabundle chain (in reverse order)
        # cert[i] is signed by cert[i-1] (going backwards from the end)
        for i in range(len(certs) - 1, 1, -1):
            child = certs[i]
            parent = certs[i - 1]

            try:
                parent.public_key().verify(
                    child.signature,
                    child.tbs_certificate_bytes,
                    ec.ECDSA(child.signature_hash_algorithm)
                )
            except InvalidSignature:
                return False, f"CA bundle certificate {i} signature verification failed"

        # The first cert in cabundle (certs[1]) should be the root or signed by root
        # Check if it's self-signed (is the root itself)
        first_cabundle_cert = certs[1]
        if first_cabundle_cert.subject == first_cabundle_cert.issuer:
            # Self-signed, verify it matches the expected root
            if first_cabundle_cert.subject != root_cert.subject:
                return False, "Self-signed certificate does not match expected root"
            return True, "Certificate chain verified successfully (root in bundle)"
        else:
            # Signed by root
            try:
                root_cert.public_key().verify(
                    first_cabundle_cert.signature,
                    first_cabundle_cert.tbs_certificate_bytes,
                    ec.ECDSA(first_cabundle_cert.signature_hash_algorithm)
                )
                return True, "Certificate chain verified successfully"
            except InvalidSignature:
                return False, "Root certificate verification failed"

    except Exception as e:
        return False, f"Certificate chain verification error: {str(e)}"

def verify_cose_signature(cose_structure, payload, root_cert_pem):
    """Verify the COSE Sign1 signature"""
    try:
        protected_headers = cose_structure['protected_headers']
        protected_headers_bytes = cose_structure['protected_headers_bytes']
        signature = cose_structure['signature']

        # Get the algorithm (should be ES384)
        alg = protected_headers.get(1)
        if alg != ES384_ALGORITHM_ID:
            return False, f"Unsupported algorithm: {alg} (expected {ES384_ALGORITHM_ID} for ES384)"

        # Load the attestation document to get the certificate
        doc = cbor2.loads(payload)
        cert_der = doc.get('certificate')
        if not cert_der:
            return False, "No certificate found in attestation document"

        # Load the certificate
        cert = x509.load_der_x509_certificate(cert_der, default_backend())
        public_key = cert.public_key()

        # Construct the Sig_structure for COSE Sign1
        # Sig_structure = [
        #   context = "Signature1",
        #   body_protected = protected headers (raw bytes),
        #   external_aad = empty,
        #   payload = payload
        # ]
        sig_structure = [
            "Signature1",
            protected_headers_bytes,  # Use raw bytes, not re-encoded
            b'',  # external_aad
            payload
        ]
        sig_structure_bytes = cbor2.dumps(sig_structure)

        # Convert signature from IEEE P1363 format to DER format
        # ES384 uses 48-byte r and s values (96 bytes total)
        if len(signature) != ES384_SIGNATURE_LENGTH:
            return False, f"Invalid signature length: {len(signature)} (expected {ES384_SIGNATURE_LENGTH} for ES384)"

        r_bytes = signature[:ES384_R_S_LENGTH]
        s_bytes = signature[ES384_R_S_LENGTH:]
        r = int.from_bytes(r_bytes, 'big')
        s = int.from_bytes(s_bytes, 'big')

        # Encode as DER
        der_signature = utils.encode_dss_signature(r, s)

        # Verify the signature
        try:
            public_key.verify(
                der_signature,
                sig_structure_bytes,
                ec.ECDSA(hashes.SHA384())
            )
            return True, "COSE signature verified successfully"
        except InvalidSignature:
            return False, "COSE signature verification failed"

    except Exception as e:
        return False, f"COSE signature verification error: {str(e)}"

def display_cose_structure(cose):
    """Display COSE Sign1 structure information"""
    print("\n" + "=" * SEPARATOR_WIDTH)
    print("COSE SIGN1 STRUCTURE")
    print("=" * SEPARATOR_WIDTH)
    print(f"\nProtected Headers: {cose['protected_headers']}")
    print(f"Signature Length: {len(cose['signature'])} bytes")

def display_key_information(doc, cose):
    """Display key attestation document information"""
    print("\n" + "=" * SEPARATOR_WIDTH)
    print("ATTESTATION DOCUMENT")
    print("=" * SEPARATOR_WIDTH)

    # Certificate Information
    if 'certificate' in doc:
        cert_info = get_certificate_info(doc['certificate'])
        print("\nCertificate Status:")
        print(f"  {cert_info['status']} - {cert_info['status_detail']}")
        print(f"  Valid From:  {format_datetime(cert_info['not_before'])}")
        print(f"  Valid Until: {format_datetime(cert_info['not_after'])}")
        if cert_info['subject_cn']:
            print(f"  Subject CN:  {cert_info['subject_cn']}")

    if 'module_id' in doc:
        print(f"\nModule ID: {doc['module_id']}")

    if 'timestamp' in doc:
        ts = doc['timestamp']
        if isinstance(ts, int):
            dt = datetime.fromtimestamp(ts / 1000, tz=timezone.utc)
            print(f"Timestamp: {ts} ({format_datetime(dt)})")
        else:
            print(f"Timestamp: {ts}")

    if 'digest' in doc:
        print(f"Digest: {doc['digest']}")

    if cose:
        print(f"\nSignature ({len(cose['signature'])} bytes):")
        print(cose['signature'].hex())

    if 'pcrs' in doc:
        pcrs = doc['pcrs']
        non_zero_pcrs = filter_nonzero_pcrs(pcrs)

        if isinstance(non_zero_pcrs, dict):
            print(f"\nPCR Values ({len(non_zero_pcrs)} non-zero out of {len(pcrs)}):")
            for idx in sorted(non_zero_pcrs.keys()):
                pcr = non_zero_pcrs[idx]
                print(f"  PCR[{idx}]: {pcr if isinstance(pcr, str) else pcr.hex()}")
        elif isinstance(non_zero_pcrs, list):
            total_pcrs = len(pcrs) if isinstance(pcrs, list) else 0
            print(f"\nPCR Values ({len(non_zero_pcrs)} non-zero out of {total_pcrs}):")
            for i, pcr in non_zero_pcrs:
                print(f"  PCR[{i}]: {pcr.hex() if isinstance(pcr, bytes) else pcr}")

    if 'public_key' in doc:
        pk = doc['public_key']
        if isinstance(pk, bytes):
            print(f"\nPublic Key ({len(pk)} bytes):")
            print(pk.hex())
        else:
            print(f"\nPublic Key: N/A")

    if 'user_data' in doc:
        print(f"\nUser Data:")
        try:
            user_data_decoded = doc['user_data'].decode('utf-8')
            print(f"  {user_data_decoded}")
        except (UnicodeDecodeError, AttributeError):
            ud = doc['user_data']
            if isinstance(ud, bytes):
                print(f"  Binary ({len(ud)} bytes): {ud.hex()}")
            else:
                print(f"  {ud}")

    if 'nonce' in doc:
        nonce = doc['nonce']
        print(f"\nNonce: {nonce.hex() if isinstance(nonce, bytes) else nonce}")

def run_verification(doc, cose, payload_bytes, args):
    """Run attestation verification"""
    print("\n" + "=" * SEPARATOR_WIDTH)
    print("VERIFICATION RESULTS")
    print("=" * SEPARATOR_WIDTH)

    # Load root certificate
    try:
        with open(args.root_cert, 'r') as f:
            root_cert_pem = f.read()
    except FileNotFoundError:
        print(f"\n✗ ERROR: Root certificate not found at {args.root_cert}")
        exit(1)

    # Verify COSE signature
    sig_valid, sig_msg = verify_cose_signature(cose, payload_bytes, root_cert_pem)
    print(f"\n[1] COSE Signature Verification")
    print(f"  Status:  {'✓ VALID' if sig_valid else '✗ INVALID'}")
    print(f"  Details: {sig_msg}")

    # Verify certificate chain
    chain_valid = False
    if 'cabundle' in doc and 'certificate' in doc:
        # Build the full chain: [enclave cert, ca bundle certs...]
        cert_chain = [doc['certificate']] + doc['cabundle']
        chain_valid, chain_msg = verify_certificate_chain(cert_chain, root_cert_pem)
        print(f"\n[2] Certificate Chain Verification")
        print(f"  Status:  {'✓ VALID' if chain_valid else '✗ INVALID'}")
        print(f"  Details: {chain_msg}")
        print(f"  Chain Length: {len(cert_chain)} certificates")

        # Show certificate details for each cert in the chain
        print(f"\n  Certificate Chain Details:")
        expired_count = 0
        for i, cert_der in enumerate(cert_chain):
            cert_info = get_certificate_info(cert_der)

            # Count expired certificates
            if '✗ EXPIRED' in cert_info['status']:
                expired_count += 1

            # Determine cert type based on self-signed status and position
            if cert_info['is_self_signed']:
                cert_type = "Root CA"
            elif i == 0:
                cert_type = "Enclave Cert"
            else:
                cert_type = "Intermediate CA"

            print(f"\n    [{i}] {cert_type}")
            if cert_info['subject_cn']:
                print(f"      Subject CN:  {cert_info['subject_cn']}")
            if cert_info['issuer_cn']:
                print(f"      Issuer CN:   {cert_info['issuer_cn']}")
            print(f"      Status:      {cert_info['status']}")
            print(f"      Valid From:  {format_datetime(cert_info['not_before'])}")
            print(f"      Valid Until: {format_datetime(cert_info['not_after'])}")
            print(f"      {cert_info['status_detail']}")

        if expired_count > 0:
            print(f"\n  ⚠️  WARNING: {expired_count} certificate(s) in chain are expired!")
            print(f"     Note: Signature verification checks cryptographic validity, not expiry dates.")
    else:
        print(f"\n[2] Certificate Chain Verification")
        print(f"  Status:  ⊘ SKIPPED")
        print(f"  Details: Certificates not found in attestation")

    # Overall result
    print("\n" + "=" * SEPARATOR_WIDTH)
    overall_valid = sig_valid and (chain_valid if 'cabundle' in doc else True)
    if overall_valid:
        print("OVERALL: ✓ ATTESTATION VERIFIED SUCCESSFULLY")
    else:
        print("OVERALL: ✗ ATTESTATION VERIFICATION FAILED")
    print("=" * SEPARATOR_WIDTH)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Decode and verify AWS Nitro attestation documents')
    parser.add_argument('--attestation', default='attestation', help='Path to attestation file (default: attestation)')
    parser.add_argument('--verify', action='store_true', help='Verify the attestation signature and certificate chain')
    parser.add_argument('--root-cert', default='root.pem', help='Path to AWS root certificate (default: root.pem)')
    parser.add_argument('--full', action='store_true', help='Show full public key and signature')
    args = parser.parse_args()

    print("\n" + "=" * SEPARATOR_WIDTH)
    print("AWS NITRO ATTESTATION DECODER")
    print("=" * SEPARATOR_WIDTH)
    print(f"Attestation file: {args.attestation}")
    if args.verify:
        print(f"Root certificate: {args.root_cert}")

    # Decode the attestation document
    result = decode_attestation(args.attestation)

    # Extract components
    if isinstance(result, dict) and 'document' in result:
        doc = result['document']
        cose = result['cose']
        payload_bytes = result.get('payload_bytes')
        display_cose_structure(cose)
    else:
        doc = result
        cose = None
        payload_bytes = None

    # Show full document structure if requested
    if args.full:
        print("\n[Full Attestation Document Structure]")
        print("-" * SEPARATOR_WIDTH)
        formatted = format_attestation(doc)
        pprint(formatted, width=120)

    # Display key information
    if isinstance(doc, dict):
        display_key_information(doc, cose)
    else:
        print(f"\n(Attestation document is a {type(doc).__name__}, not a dict)")

    # Run verification if requested
    if args.verify and cose and payload_bytes:
        run_verification(doc, cose, payload_bytes, args)

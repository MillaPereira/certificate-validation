from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import ExtensionOID
import datetime

def load_certificates(file_path):
    with open(file_path, 'rb') as file:
        data = file.read()
        certs = []
        current_cert = b''
        for line in data.splitlines(True):
            if line.startswith(b'-----BEGIN CERTIFICATE-----'):
                current_cert = line
            elif line.startswith(b'-----END CERTIFICATE-----'):
                current_cert += line
                certs.append(x509.load_pem_x509_certificate(current_cert, default_backend()))
                current_cert = b''
            else:
                current_cert += line
        return certs

def verify_cert_chain(cert_chain, ca_bundle_path):
    ca_certs = load_certificates(ca_bundle_path)
    ca_certs_dict = {cert.subject: cert for cert in ca_certs}

    for i in range(len(cert_chain)-1):
        issuer_cert = ca_certs_dict.get(cert_chain[i+1].subject)
        if issuer_cert is None:
            return False, "Certificado do emissor não encontrado."

        # Verifique a assinatura do certificado
        try:
            cert_chain[i].public_key().verify(
                cert_chain[i].signature,
                cert_chain[i].tbs_certificate_bytes,
                cert_chain[i].signature_hash_algorithm
            )
        except Exception as e:
            return False, "Falha na verificação da assinatura: " + str(e)

    # Verifique se o certificado raiz está na lista CA
    root_cert = cert_chain[-1]
    if root_cert.subject not in ca_certs_dict:
        return False, "Certificado raiz não confiável."

    return True, "A cadeia de certificados é confiável."

# Carregar cadeia de certificados
cert_chain_path = '0-gts-root-r1.crt'
ca_bundle_path = 'getCertificateChain-main/cacert.pem'

cert_chain = load_certificates(cert_chain_path)
is_trusted, message = verify_cert_chain(cert_chain, ca_bundle_path)
print(message)

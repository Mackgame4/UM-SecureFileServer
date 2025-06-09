from cryptography import x509
from datetime import timezone
#from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID
from datetime import datetime
import os

def cert_load(fname):
    """lê certificado de ficheiro"""
    with open(fname, "rb") as fcert:
        cert = x509.load_pem_x509_certificate(fcert.read())
    return cert

def cert_validtime(cert, now=None):
    """Valida período de validade do certificado com tratamento correto de timezone"""
    try:
        # Garante que now está em UTC
        now = datetime.now(timezone.utc) if now is None else now
        
        # Verifica validade
        if now < cert.not_valid_before_utc:
            print(f"⚠️ Certificado ainda não válido (válido a partir de {cert.not_valid_before_utc})")
            return False
            
        if now > cert.not_valid_after_utc:
            print(f"⚠️ Certificado expirado (expirou em {cert.not_valid_after_utc})")
            return False
            
        # print("✅ Certificado dentro do período válido")
        return True
        
    except Exception as e:
        print(f"❌ Erro na verificação de validade: {str(e)}")
        return False


def cert_validsubject(cert, attrs=[]):
    """verifica atributos do campo 'subject'. 'attrs'
    é uma lista de pares '(attr,value)' que condiciona
    os valores de 'attr' a 'value'."""
    for attr in attrs:
        if cert.subject.get_attributes_for_oid(attr[0])[0].value != attr[1]:
            raise x509.verification.VerificationError(
                "Certificate subject does not match expected value"
            )


def cert_validexts(cert, policy=[]):
    """valida extensões do certificado.
    'policy' é uma lista de pares '(ext,pred)' onde 'ext' é o OID de uma extensão e 'pred'
    o predicado responsável por verificar o conteúdo dessa extensão."""
    for check in policy:
        ext = cert.extensions.get_extension_for_oid(check[0]).value
        if not check[1](ext):
            raise x509.verification.VerificationError(
                "Certificate extensions does not match expected value"
            )

def valida_cert(cert, subject):
    try:
        # print(cert.public_bytes(encoding=serialization.Encoding.PEM))
        # obs: pressupõe que a cadeia de certifica só contém 2 níveis
        base_dir = os.path.dirname(os.path.abspath(__file__))
        cert_path = os.path.join(base_dir, "../../projCA/VAULT_CA.crt")
        cert.verify_directly_issued_by(cert_load(cert_path))
        # verificar período de validade...
        try:
            cert_validtime(cert)
        except:
            print("[DEBUG] Certificado inválido por causa da data ")
            return False
        # verificar identidade... (e.g.)
        try:
           # print(f"[DEBUG] Validando subject - Esperado: {subject}")
            cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            
            cert_validsubject(cert, [(x509.NameOID.COMMON_NAME, subject)])
           # print("[DEBUG] Validação do subject bem-sucedida")
        
        except x509.verification.VerificationError as e:
           # print(f"[DEBUG] Falha na validação do subject: {str(e)}")
            return False
        except Exception as e:
            # print(f"[DEBUG] Erro inesperado na validação do subject: {str(e)}")
            return False
            
        # verificar aplicabilidade... (e.g.)
        # cert_validexts(
        #     cert,
        #     [
        #         (
        #             x509.ExtensionOID.EXTENDED_KEY_USAGE,
        #             lambda e: x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH in e,
        #         )
        #     ],
        # )
        try:
            key_usage = cert.extensions.get_extension_for_oid(x509.ExtensionOID.KEY_USAGE).value
           # print(f"[DEBUG] Key Usage encontrado: {key_usage}")
            # Vverify if the key usage is set for digital signature
            
            if not key_usage.digital_signature:
                print("[DEBUG] Certificado não permite uso para assinatura digital")
                return False
        except x509.ExtensionNotFound:
            print("[DEBUG] Aviso: Key Usage extension não encontrada")

    except:
        return False

    return True
use std::{
    env,
    fs::read,
    path::{Path, PathBuf},
};
use x509_cert::Certificate;
use x509_verifier::{
    types::TrustAnchor,
    verify::{key_usage::ServerProfile, verify_cert_chain, VerifyOptions},
    CertificatePool,
};

fn test_cert_chain_verify<P>(base_path: P)
where
    P: AsRef<Path>,
{
    let cert_path = base_path.as_ref().join("cert.crt");
    let ca_path = base_path.as_ref().join("ca.crt");

    let certs =
        Certificate::load_pem_chain(&read(cert_path).expect("Failed to read certificate file"))
            .expect("Failed to parse certificates");
    let cas = Certificate::load_pem_chain(&read(ca_path).expect("Failed to read certificate file"))
        .expect("Failed to parse CA certificates");
    let tas: Vec<TrustAnchor> = cas
        .into_iter()
        .map(TrustAnchor::try_from)
        .collect::<Result<_, _>>()
        .unwrap();

    let mut cert_iter = certs.into_iter();
    let end_cert = cert_iter.next().expect("No certificate found");
    let mut cert_pool = CertificatePool::default();
    cert_pool.extend(tas);
    cert_pool.extend(cert_iter);

    let options = VerifyOptions::default();
    verify_cert_chain(&cert_pool, &end_cert, &options, &ServerProfile::default())
        .expect("Failed to verify certificate chain");
}

fn get_base_path() -> PathBuf {
    let cargo_manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    cargo_manifest_dir.join("assets/cert_chain_verify")
}

#[test]
fn test_cert_chain_verify_simple() {
    test_cert_chain_verify(get_base_path().join("simple"));
}

#[test]
fn test_cert_chain_verify_google() {
    test_cert_chain_verify(get_base_path().join("google"));
}

#[test]
#[should_panic]
fn test_cert_chain_verify_bad_cert() {
    test_cert_chain_verify(get_base_path().join("bad_cert"));
}

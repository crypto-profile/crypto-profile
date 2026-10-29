#![allow(missing_docs)]
use crypto_profile_awslc3::rustls;
use crypto_profile_awslc3::test_support::{Pki, pki};
use crypto_profile_awslc3::tls::{Policy, client_builder, server_builder};
use crypto_profile_awslc3::{
    CipherSuite, KxGroup, SignatureAlgorithm, TlsSignatureScheme, TlsVersion,
};
use std::io::{BufRead, BufReader};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};

const GROUP: u16 = 0x11ED;
const LIMIT: Duration = Duration::from_secs(30);

fn e(x: impl std::fmt::Display) -> String {
    x.to_string()
}

struct Reap(Child);

impl Drop for Reap {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn openssl() -> Result<String, String> {
    let bin = std::env::var("CRYPTO_PROFILE_OPENSSL")
        .map_err(|_| "set CRYPTO_PROFILE_OPENSSL to an OpenSSL 3.5 or later binary".to_string())?;
    let out = Command::new(&bin)
        .arg("version")
        .output()
        .map_err(|x| format!("{bin}: {x}"))?;
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    let mut parts = text
        .split_whitespace()
        .nth(1)
        .unwrap_or_default()
        .split('.')
        .map(|p| p.parse::<u32>().unwrap_or(0));
    let (major, minor) = (parts.next().unwrap_or(0), parts.next().unwrap_or(0));
    if text.starts_with("OpenSSL ") && (major, minor) >= (3, 5) {
        Ok(bin)
    } else {
        Err(format!("{bin} is {text:?}, not OpenSSL 3.5 or later"))
    }
}

fn policy() -> Policy {
    Policy {
        peer_certificate_rule: None,
        versions: vec![TlsVersion::Tls13],
        cipher_suites: vec![CipherSuite::Tls13Aes256GcmSha384],
        kx_groups: vec![KxGroup::Secp384r1MlKem1024],
        signature_schemes: vec![TlsSignatureScheme::EcdsaNistp384Sha384],
    }
}

fn files(p: &Pki, tag: &str) -> Result<(Scratch, PathBuf, PathBuf, PathBuf), String> {
    let dir = Scratch(std::env::temp_dir().join(format!(
        "crypto-profile-interop-{tag}-{}",
        std::process::id()
    )));
    std::fs::create_dir_all(&dir.0).map_err(e)?;
    let write = |name: &str, label: &str, der: &[u8]| -> Result<PathBuf, String> {
        let path = dir.0.join(name);
        std::fs::write(&path, pem::encode(&pem::Pem::new(label, der.to_vec()))).map_err(e)?;
        Ok(path)
    };
    let leaf = write("leaf.pem", "CERTIFICATE", &p.chain[0])?;
    let key = write("key.pem", "PRIVATE KEY", p.key.pkcs8_der())?;
    let ca = write("ca.pem", "CERTIFICATE", &p.ca)?;
    Ok((dir, leaf, key, ca))
}

fn timed(sock: &TcpStream) -> Result<(), String> {
    sock.set_read_timeout(Some(LIMIT)).map_err(e)?;
    sock.set_write_timeout(Some(LIMIT)).map_err(e)
}

fn accept_within(listener: &TcpListener) -> Result<TcpStream, String> {
    listener.set_nonblocking(true).map_err(e)?;
    let deadline = Instant::now() + LIMIT;
    loop {
        match listener.accept() {
            Ok((sock, _)) => {
                sock.set_nonblocking(false).map_err(e)?;
                timed(&sock)?;
                return Ok(sock);
            }
            Err(x) if x.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(x) => return Err(format!("no connection within {LIMIT:?}: {x}")),
        }
    }
}

fn group_of(c: &rustls::CommonState) -> Option<u16> {
    c.negotiated_key_exchange_group()
        .map(|g| u16::from_be_bytes(g.name().to_array()))
}

#[test]
#[ignore = "needs OpenSSL 3.5 or later: ci/openssl-interop.sh"]
fn our_client_negotiates_secp384r1mlkem1024_with_openssl_s_server() -> Result<(), String> {
    let bin = openssl()?;
    let p = pki(
        SignatureAlgorithm::EcdsaP384Sha384,
        SignatureAlgorithm::EcdsaP384Sha384,
    )?;
    let (_dir, leaf, key, _) = files(&p, "server")?;
    let port = TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .map_err(e)?
        .port();
    let mut server = Reap(
        Command::new(&bin)
            .args([
                "s_server",
                "-accept",
                &format!("127.0.0.1:{port}"),
                "-naccept",
                "1",
                "-tls1_3",
                "-groups",
                "SecP384r1MLKEM1024",
            ])
            .arg("-cert")
            .arg(&leaf)
            .arg("-key")
            .arg(&key)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(e)?,
    );
    let stdout = server.0.stdout.take().ok_or("no s_server stdout")?;
    let (ready, listening) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            match line {
                Ok(l) if l.starts_with("ACCEPT") => {
                    let _ = ready.send(());
                }
                Ok(_) => {}
                Err(_) => return,
            }
        }
    });
    listening
        .recv_timeout(LIMIT)
        .map_err(|x| format!("s_server did not listen within {LIMIT:?}: {x}"))?;
    let cfg = client_builder(&policy())
        .map_err(e)?
        .with_root_certificates(p.roots)
        .with_no_client_auth();
    let mut conn = rustls::ClientConnection::new(Arc::new(cfg), "localhost".try_into().map_err(e)?)
        .map_err(e)?;
    let mut sock = TcpStream::connect(("127.0.0.1", port)).map_err(e)?;
    timed(&sock)?;
    while conn.is_handshaking() {
        conn.complete_io(&mut sock).map_err(e)?;
    }
    let group = group_of(&conn);
    conn.send_close_notify();
    let _ = conn.complete_io(&mut sock);
    drop(sock);
    drop(server);
    assert_eq!(group, Some(GROUP));
    Ok(())
}

#[test]
#[ignore = "needs OpenSSL 3.5 or later: ci/openssl-interop.sh"]
fn openssl_s_client_negotiates_secp384r1mlkem1024_with_our_server() -> Result<(), String> {
    let bin = openssl()?;
    let p = pki(
        SignatureAlgorithm::EcdsaP384Sha384,
        SignatureAlgorithm::EcdsaP384Sha384,
    )?;
    let (_dir, _, _, ca) = files(&p, "client")?;
    let listener = TcpListener::bind("127.0.0.1:0").map_err(e)?;
    let port = listener.local_addr().map_err(e)?.port();
    let der = rustls::pki_types::PrivateKeyDer::Pkcs8(p.key.pkcs8_der().to_vec().into());
    let cfg = server_builder(&policy())
        .map_err(e)?
        .with_no_client_auth()
        .with_single_cert(p.chain.clone(), der)
        .map_err(e)?;
    let serve = std::thread::spawn(move || -> Result<Option<u16>, String> {
        let mut sock = accept_within(&listener)?;
        let mut conn = rustls::ServerConnection::new(Arc::new(cfg)).map_err(e)?;
        while conn.is_handshaking() {
            conn.complete_io(&mut sock).map_err(e)?;
        }
        let group = group_of(&conn);
        conn.send_close_notify();
        let _ = conn.complete_io(&mut sock);
        Ok(group)
    });
    let out = Command::new(&bin)
        .args([
            "s_client",
            "-connect",
            &format!("127.0.0.1:{port}"),
            "-servername",
            "localhost",
            "-tls1_3",
            "-groups",
            "SecP384r1MLKEM1024",
            "-verify_return_error",
            "-brief",
        ])
        .arg("-CAfile")
        .arg(&ca)
        .stdin(Stdio::null())
        .output()
        .map_err(e)?;
    let transcript = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let served = serve
        .join()
        .map_err(|_| "server thread panicked")?
        .map_err(|x| format!("{x}\n{transcript}"))?;
    assert_eq!(served, Some(GROUP), "{transcript}");
    assert!(out.status.success(), "{transcript}");
    assert!(transcript.contains("SecP384r1MLKEM1024"), "{transcript}");
    Ok(())
}

#[test]
#[ignore = "needs OpenSSL 3.5 or later: ci/openssl-interop.sh"]
fn peer_certificate_cnsa1_p256_tls12_sha384() -> Result<(), String> {
    use crypto_profile_awslc3::test_support::peer_certificate_pki;
    use crypto_profile_awslc3::tls::{server_cert_verifier_builder, strict_client_builder};
    use crypto_profile_awslc3::{
        Options, PeerCertificateViolation, PeerCurve, PeerKey, Profile, TlsError, resolve,
    };
    let bin = openssl()?;
    let p = peer_certificate_pki(
        SignatureAlgorithm::EcdsaP384Sha384,
        None,
        SignatureAlgorithm::EcdsaP256Sha256,
    )?;
    let scratch =
        Scratch(std::env::temp_dir().join(format!("crypto-profile-p256-{}", std::process::id())));
    std::fs::create_dir_all(&scratch.0).map_err(e)?;
    let leaf = scratch.0.join("leaf.pem");
    let key = scratch.0.join("key.pem");
    std::fs::write(
        &leaf,
        pem::encode(&pem::Pem::new("CERTIFICATE", p.chain[0].to_vec())),
    )
    .map_err(e)?;
    std::fs::write(
        &key,
        pem::encode(&pem::Pem::new("PRIVATE KEY", p.key.secret_der().to_vec())),
    )
    .map_err(e)?;
    for strict in [false, true] {
        let mut policy = resolve(
            Profile::Cnsa1,
            Options {
                peer_certificates_match_profile: strict,
                ..Options::default()
            },
        )
        .map_err(e)?
        .tls;
        policy.versions = vec![TlsVersion::Tls12];
        policy.cipher_suites = vec![CipherSuite::Tls12EcdheEcdsaAes256GcmSha384];
        policy.kx_groups = vec![KxGroup::Secp384r1, KxGroup::Secp256r1];
        policy.signature_schemes = vec![TlsSignatureScheme::EcdsaNistp384Sha384];
        let verifier = server_cert_verifier_builder(Arc::new(p.roots.clone()), &policy)
            .map_err(e)?
            .build()
            .map_err(e)?;
        let builder = if strict {
            strict_client_builder(&policy, verifier).map_err(e)?
        } else {
            client_builder(&policy)
                .map_err(e)?
                .dangerous()
                .with_custom_certificate_verifier(verifier)
        };
        let cfg = builder.with_no_client_auth();
        let port = TcpListener::bind("127.0.0.1:0")
            .and_then(|l| l.local_addr())
            .map_err(e)?
            .port();
        let mut server = Reap(
            Command::new(&bin)
                .args([
                    "s_server",
                    "-accept",
                    &format!("127.0.0.1:{port}"),
                    "-naccept",
                    "1",
                    "-tls1_2",
                    "-sigalgs",
                    "ECDSA+SHA384",
                    "-groups",
                    "P-384:P-256",
                ])
                .arg("-cert")
                .arg(&leaf)
                .arg("-key")
                .arg(&key)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .map_err(e)?,
        );
        let stdout = server.0.stdout.take().ok_or("no s_server stdout")?;
        let (ready, listening) = mpsc::channel();
        let reader = std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                match line {
                    Ok(l) if l.starts_with("ACCEPT") => {
                        let _ = ready.send(());
                    }
                    Ok(_) => {}
                    Err(_) => return,
                }
            }
        });
        listening.recv_timeout(LIMIT).map_err(e)?;
        let mut conn =
            rustls::ClientConnection::new(Arc::new(cfg), "localhost".try_into().map_err(e)?)
                .map_err(e)?;
        let mut sock = TcpStream::connect(("127.0.0.1", port)).map_err(e)?;
        timed(&sock)?;
        let result = (|| {
            while conn.is_handshaking() {
                conn.complete_io(&mut sock)?;
            }
            Ok::<_, std::io::Error>(())
        })();
        if strict {
            let error = result.expect_err("strict P-256 leaf accepted");
            let cause = error
                .get_ref()
                .and_then(|cause| cause.downcast_ref::<rustls::Error>())
                .expect("rustls error");
            let rustls::Error::InvalidCertificate(rustls::CertificateError::Other(
                rustls::OtherError(cause),
            )) = cause
            else {
                panic!("missing typed refusal: {cause:?}");
            };
            assert_eq!(
                cause.downcast_ref::<TlsError>(),
                Some(&TlsError::PeerCertificate {
                    profile: Profile::Cnsa1,
                    violation: PeerCertificateViolation::LeafKey(PeerKey::Ec(PeerCurve::P256))
                })
            );
        } else {
            result.map_err(e)?;
            assert_eq!(
                conn.protocol_version(),
                Some(rustls::ProtocolVersion::TLSv1_2)
            );
        }
        drop(sock);
        drop(server);
        reader.join().map_err(|_| "peer output reader panicked")?;
    }
    Ok(())
}

#[test]
#[ignore = "needs OpenSSL 3.5 or later: ci/openssl-interop.sh"]
fn peer_certificate_cnsa1_p256_client_tls12_sha384() -> Result<(), String> {
    use crypto_profile_awslc3::test_support::{peer_certificate_pki, pki};
    use crypto_profile_awslc3::tls::{
        client_cert_verifier_builder, server_builder, strict_server_builder,
    };
    use crypto_profile_awslc3::{Options, Profile, resolve};
    use crypto_profile_awslc3::{PeerCertificateViolation, PeerCurve, PeerKey, TlsError};
    let bin = openssl()?;
    let p = peer_certificate_pki(
        SignatureAlgorithm::EcdsaP384Sha384,
        None,
        SignatureAlgorithm::EcdsaP256Sha256,
    )?;
    let (scratch, leaf, key) = {
        let dir = Scratch(
            std::env::temp_dir().join(format!("crypto-profile-p256-client-{}", std::process::id())),
        );
        std::fs::create_dir_all(&dir.0).map_err(e)?;
        let leaf = dir.0.join("leaf.pem");
        let key = dir.0.join("key.pem");
        std::fs::write(
            &leaf,
            pem::encode(&pem::Pem::new("CERTIFICATE", p.chain[0].to_vec())),
        )
        .map_err(e)?;
        std::fs::write(
            &key,
            pem::encode(&pem::Pem::new("PRIVATE KEY", p.key.secret_der().to_vec())),
        )
        .map_err(e)?;
        (dir, leaf, key)
    };
    let server_pki = pki(
        SignatureAlgorithm::EcdsaP384Sha384,
        SignatureAlgorithm::EcdsaP384Sha384,
    )?;
    let ca = scratch.0.join("server-ca.pem");
    std::fs::write(
        &ca,
        pem::encode(&pem::Pem::new("CERTIFICATE", server_pki.ca.to_vec())),
    )
    .map_err(e)?;
    for strict in [false, true] {
        let mut policy = resolve(
            Profile::Cnsa1,
            Options {
                peer_certificates_match_profile: strict,
                ..Options::default()
            },
        )
        .map_err(e)?
        .tls;
        policy.versions = vec![TlsVersion::Tls12];
        policy.cipher_suites = vec![CipherSuite::Tls12EcdheEcdsaAes256GcmSha384];
        policy.kx_groups = vec![KxGroup::Secp384r1];
        policy.signature_schemes = vec![TlsSignatureScheme::EcdsaNistp384Sha384];
        let verifier = client_cert_verifier_builder(Arc::new(p.roots.clone()), &policy)
            .map_err(e)?
            .build()
            .map_err(e)?;
        let builder = if strict {
            strict_server_builder(&policy, verifier).map_err(e)?
        } else {
            server_builder(&policy)
                .map_err(e)?
                .with_client_cert_verifier(verifier)
        };
        let server_cfg = builder
            .with_single_cert(
                server_pki.chain.clone(),
                rustls::pki_types::PrivateKeyDer::Pkcs8(server_pki.key.pkcs8_der().to_vec().into()),
            )
            .map_err(e)?;
        let listener = TcpListener::bind("127.0.0.1:0").map_err(e)?;
        let port = listener.local_addr().map_err(e)?.port();
        let server = std::thread::spawn(move || -> Result<(), std::io::Error> {
            let mut sock = accept_within(&listener).map_err(std::io::Error::other)?;
            let mut conn = rustls::ServerConnection::new(Arc::new(server_cfg))
                .map_err(std::io::Error::other)?;
            while conn.is_handshaking() {
                conn.complete_io(&mut sock)?;
            }
            conn.send_close_notify();
            conn.write_tls(&mut sock)?;
            Ok(())
        });
        let out = Command::new(&bin)
            .args([
                "s_client",
                "-connect",
                &format!("127.0.0.1:{port}"),
                "-tls1_2",
                "-sigalgs",
                "ECDSA+SHA384",
                "-groups",
                "P-384",
                "-cert",
            ])
            .arg(&leaf)
            .arg("-key")
            .arg(&key)
            .arg("-CAfile")
            .arg(&ca)
            .args(["-verify_return_error", "-trace", "-brief", "-quiet"])
            .stdin(Stdio::null())
            .output()
            .map_err(e)?;
        let transcript = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        let server_result = server.join().map_err(|_| "server thread panicked")?;
        if strict {
            let error = server_result.expect_err("strict P-256 client leaf accepted");
            let cause = error
                .get_ref()
                .and_then(|source| source.downcast_ref::<rustls::Error>())
                .expect("rustls certificate error");
            let rustls::Error::InvalidCertificate(rustls::CertificateError::Other(
                rustls::OtherError(cause),
            )) = cause
            else {
                panic!("missing typed refusal: {cause:?}");
            };
            assert_eq!(
                cause.downcast_ref::<TlsError>(),
                Some(&TlsError::PeerCertificate {
                    profile: Profile::Cnsa1,
                    violation: PeerCertificateViolation::LeafKey(PeerKey::Ec(PeerCurve::P256))
                })
            );
            assert!(
                !out.status.success(),
                "strict OpenSSL client unexpectedly succeeded: {transcript}"
            );
        } else {
            server_result.map_err(e)?;
            assert!(out.status.success(), "OpenSSL client failed: {transcript}");
            assert!(
                transcript.contains("CertificateVerify, Length="),
                "missing CertificateVerify: {transcript}"
            );
            assert!(
                transcript.contains("ecdsa_secp384r1_sha384 (0x0503)"),
                "wrong CertificateVerify scheme: {transcript}"
            );
        }
    }
    drop(scratch);
    Ok(())
}

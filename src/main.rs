use pretty_hex::*;
use sev::firmware::guest::AttestationReport;
use sha2::{Digest, Sha512};
use std::{fs, str::FromStr};
use tempfile::tempdir_in;

use tss_esapi::{
    abstraction::ek,
    interface_types::{
        algorithm::AsymmetricAlgorithm,
        resource_handles::Hierarchy,
    },
    TctiNameConf,
    traits::Marshall,
    Context,
};

fn main() {

    println!("Getting vTPM attestation report from SVSM uisng Linux configfs_tsm");
    //create temp directory
    let tmp_dir =
        tempdir_in("/sys/kernel/config/tsm/report").expect("Failed to create temp directory");
    println!("Temp dir: {:?}", tmp_dir);

    //write 1 to svsm file
    fs::write(tmp_dir.path().join("svsm"), "1").expect("Failed to write to svsm file");

    let nonce: [u8; 64] = [0xff; 64];
    // write nonce to inblob file
    fs::write(tmp_dir.path().join("inblob"), &nonce).expect("Failed to write to inblob file");
    let attest_vtpm_guid = "c476f1eb-0123-45a5-9641-b4e7dde5bfe3";
    //write attest_vtpm_guid to service_guid file
    fs::write(tmp_dir.path().join("service_guid"), attest_vtpm_guid)
        .expect("Failed to write to service_guid file");
    //read outblob file
    let outblob = fs::read(tmp_dir.path().join("outblob")).expect("Failed to read outblob file");
    println!("outblob: {:?}", outblob.hex_dump());

    //write outblob to file
    fs::write("report.bin", &outblob).expect("Failed to write outblob to file");

    //read manifest file
    let manifest =
        fs::read(tmp_dir.path().join("manifestblob")).expect("Failed to read manifest file");
    println!("manifest: {:?}", manifest.hex_dump());

    // parse attestaion report in outblob
    let report: AttestationReport = bincode::deserialize(&outblob).unwrap();
    println!("report: {}", report);

    println!("Verifying that the RSA 2048 EK public in the report matches one created in vTPM using TCG Profile");
    println!("Creating EK public key using TCG Profile and comparing it to the one in the report");
    println!("{}\n", "Using TSS 2.0 Enhanced System API Rust Wrapper, tss-esapi");


    //create ek using TCG Profile
    let algorithm = AsymmetricAlgorithm::Rsa;
    let ek_public = ek::create_ek_public_from_default_template(algorithm, None)
        .expect("Failed to create ek public key");
    println!(
        "ek_public_IN: {:?}",
        ek_public.marshall().unwrap().hex_dump()
    );
    // To set your TCTI environment variable before running this code
    // use export TPM2TOOLS_TCTI="device:/dev/tpmrm0" and if using sudo use sudo -E
    // To generate ekpub to compare against you can use tpm2_createek
    // sudo -E tpm2_createek -c ek.ctx -G rsa -u ek.pub
    // sudo hexdump ek.pub
    // Get the TCTI device path from the environment variable or use a default
    let tcti_path = std::env::var("TCTI").unwrap_or_else(|_| {
        if std::path::Path::new("/dev/tpmrm0").exists() {
            "device:/dev/tpmrm0".to_string()
        } else {
            "device:/dev/tpm0".to_string()
        }
    });

    // Create a new TPM context using the TCTI device path
    let mut context = Context::new(
        TctiNameConf::from_str(&tcti_path).expect("Failed to convert TctiNameConf from string"),
    )
    .expect("Failed to create Context");
    let ek = context
        .execute_with_nullauth_session(|ctx| {
            ctx.create_primary(Hierarchy::Endorsement, ek_public, None, None, None, None)
        })
        .expect("Failed to create ek");
    let ekpub_tmpt_pub = ek
        .out_public
        .marshall()
        .expect("Failed to marshall ek public key");

    println!("tmpt_public: {:?}", ekpub_tmpt_pub.hex_dump());

    //check that ek pub from tpm matches ek pub from manifest
    assert_eq!(ekpub_tmpt_pub, manifest);
    println!("\n\n{}\n", "EK public key in the report matches the one created in vTPM!");

    //recalculate Sha512(nonce||manifest)
    println!("{}\n","Recalculating Sha512(nonce||ekpub) and verifying that it matches one in the report");
    
    //concatenate nonce and manifest
    let hash_in = nonce.to_vec();
    let hash_in = hash_in
        .into_iter()
        .chain(manifest.into_iter())
        .collect::<Vec<u8>>();
    println!("nonce||manifest: {:?}", hash_in.hex_dump());
    let sha512 = Sha512::digest(&hash_in);
    println!(
        "Sha512(nonce||manifest): {:?}",
        sha512.as_slice().hex_dump()
    );

    println!("report.report_data: {:?}", report.report_data.hex_dump());

    println!("Sha512(nonce||manifest) matches one in the report.report_data");

   

    //verify that the hash matches the digest in the report
    assert_eq!(sha512.as_slice(), report.report_data);

    //delete temp directory
    drop(tmp_dir);
}

use pretty_hex::*;
use sev::firmware::guest::AttestationReport;
use std::fs;
use tempfile::tempdir_in;

use tss_esapi::{
    abstraction::{ek, IntoKeyCustomization, KeyCustomization},
    attributes::ObjectAttributesBuilder,
    handles::{KeyHandle, NvIndexTpmHandle, TpmHandle},
    interface_types::{
        algorithm::{AsymmetricAlgorithm, HashingAlgorithm, PublicAlgorithm},
        ecc::EccCurve,
        key_bits::RsaKeyBits,
        resource_handles::{Hierarchy, NvAuth},
    },
    structures::{
        Digest, EccParameter, EccPoint, EccScheme, KeyDerivationFunctionScheme, Public,
        PublicBuilder, PublicEccParametersBuilder, PublicKeyRsa, PublicRsaParametersBuilder,
        RsaExponent, RsaScheme, SymmetricDefinitionObject,
    },
    tcti_ldr::TctiNameConf,
    traits::Marshall,
    Context,
};

fn main() {
    println!("Hello, world!");
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
    //read manifest file
    let manifest =
        fs::read(tmp_dir.path().join("manifestblob")).expect("Failed to read manifest file");
    println!("manifest: {:?}", manifest.hex_dump());

    // parse attestaion report in outblob
    let report: AttestationReport = bincode::deserialize(&outblob).unwrap();
    println!("report: {}", report);

    //create ek using TCG Profile
    let algorithm = AsymmetricAlgorithm::Rsa;
    let ek_public = ek::create_ek_public_from_default_template(algorithm, None)
        .expect("Failed to create ek public key");
    println!("ek_public_IN: {:?}", ek_public.marshall().unwrap().hex_dump());
    //Ensure that you set your TCTI environment variable before running this code
    // eg. export TPM2TOOLS_TCTI="device:/dev/tpmrm0" and if using sudo use sudo -E
    //To generate epub to compare against you can use tpm2_createek
    // sudo -E tpm2_createek -c ek.ctx -G rsa -u ek.pub
    //sudo hexdump ek.pub
    let tcti_name_conf = TctiNameConf::from_environment_variable().expect("Failed to get TCTI");
    let mut context = Context::new(tcti_name_conf).expect("Failed to create context");
    let ek = context
        .execute_with_nullauth_session(|ctx| {
            ctx.create_primary(Hierarchy::Endorsement, ek_public, None, None, None, None)
        })
        .expect("Failed to create ek");
    let ekpub_tmpt_pub = ek.out_public
        .marshall()
        .expect("Failed to marshall ek public key");
    

    println!("tmpt_public: {:?}", ekpub_tmpt_pub.hex_dump());

    //check that ek pub from tpm matches ek pub from manifest
    assert_eq!(ekpub_tmpt_pub, manifest);

    //delete temp directory
    drop(tmp_dir);
}

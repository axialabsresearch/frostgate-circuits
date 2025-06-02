use std::path::Path;
use sp1_sdk::SP1VerifyingKey;
use sp1_prover::{SP1Prover, components::CpuProverComponents};
use crate::sp1::types::{Sp1ProofType, Sp1PlugError, Sp1Backend};

pub async fn verify_proof_unified(
    backend: &Sp1Backend,
    proof_type: &Sp1ProofType,
    verifying_key: &SP1VerifyingKey,
    build_dir: &Path,
) -> Result<bool, Sp1PlugError> {
    match proof_type {
        Sp1ProofType::Core(core_proof) => {
            match backend {
                Sp1Backend::Local(prover) => {
                    prover.verify(core_proof, verifying_key)
                        .map(|_| true)
                        .map_err(|e| Sp1PlugError::Verify(format!("Core verification failed: {:?}", e)))
                }
                Sp1Backend::Network(prover) => {
                    prover.verify(core_proof, verifying_key)
                        .map(|_| true)
                        .map_err(|e| Sp1PlugError::Verify(format!("Core verification failed: {:?}", e)))
                }
            }
        }

        Sp1ProofType::PlonkBn254(plonk_proof) => {
            let local_prover = SP1Prover::<CpuProverComponents>::new();
            local_prover.verify_plonk_bn254(
                &plonk_proof.proof.0,
                verifying_key,
                &plonk_proof.public_values,
                build_dir,
            )
            .map(|_| true)
            .map_err(|e| Sp1PlugError::Verify(format!("Plonk verification failed: {:?}", e)))
        }
        Sp1ProofType::Groth16Bn254(groth_proof) => {
            let local_prover = SP1Prover::<CpuProverComponents>::new();
            local_prover.verify_groth16_bn254(
                &groth_proof.proof.0,
                verifying_key,
                &groth_proof.public_values,
                build_dir,
            )
            .map(|_| true)
            .map_err(|e| Sp1PlugError::Verify(format!("Groth16 verification failed: {:?}", e)))
        }
    }
}

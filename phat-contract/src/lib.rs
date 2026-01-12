#![cfg_attr(not(feature = "std"), no_std, no_main)]

extern crate alloc;

mod processor;
mod state;

use alloc::vec::Vec;
use ink::prelude::string::String;
use pink_extension as pink;
use scale::{Decode, Encode};

#[derive(Debug, Clone, Encode, Decode)]
#[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
pub struct WithdrawalRequest {
    pub commitment: [u8; 32],
    pub nullifier: [u8; 32],
    pub recipient: [u8; 20],
    pub amount: u128,
    pub merkle_proof: Vec<[u8; 32]>,
    pub proof_indices: Vec<bool>,
}

#[derive(Debug, Clone, Encode, Decode)]
#[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
pub struct WithdrawalResponse {
    pub success: bool,
    pub tx_hash: Option<[u8; 32]>,
    pub zk_proof: Vec<u8>,
    pub tee_attestation: Vec<u8>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Encode, Decode)]
#[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
pub struct ComplianceProof {
    pub deposit_commitment: [u8; 32],
    pub association_root: [u8; 32],
    pub zk_proof: Vec<u8>,
    pub asp_signature: Vec<u8>,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Encode, Decode)]
#[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
pub struct AuditEntry {
    pub timestamp: u64,
    pub entry_hash: [u8; 32],
    pub encrypted_details: Vec<u8>,
    pub tee_attestation: Vec<u8>,
}

#[derive(Debug, Clone, Encode, Decode, PartialEq)]
#[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
pub enum Error {
    NotAuthorized,
    InvalidProof,
    NullifierAlreadyUsed,
    InsufficientFunds,
    InvalidMerkleProof,
    EncryptionError,
    DecryptionError,
    AttestationFailed,
    EVMCallFailed,
    InvalidRequest,
    StateCorrupted,
}

#[pink::contract]
mod privacy_vault_tee {
    use super::*;
    use crate::processor::WithdrawalProcessor;
    use crate::state::EncryptedState;
    use alloc::vec;
    use pink::chain_extension::signing;

    #[ink(storage)]
    pub struct PrivacyVaultTee {
        owner: AccountId,
        evm_vault_address: [u8; 20],
        evm_chain_id: u64,
        encrypted_state: Vec<u8>,
        commitment_root: [u8; 32],
        nullifier_set: Vec<[u8; 32]>,
        asp_registry: Vec<AccountId>,
        audit_log: Vec<AuditEntry>,
        initialized: bool,
    }

    impl PrivacyVaultTee {
        #[ink(constructor)]
        pub fn new(evm_vault_address: [u8; 20], evm_chain_id: u64) -> Self {
            let caller = Self::env().caller();
            
            Self {
                owner: caller,
                evm_vault_address,
                evm_chain_id,
                encrypted_state: Vec::new(),
                commitment_root: [0u8; 32],
                nullifier_set: Vec::new(),
                asp_registry: Vec::new(),
                audit_log: Vec::new(),
                initialized: false,
            }
        }

        #[ink(constructor)]
        pub fn default() -> Self {
            Self::new([0u8; 20], 1)
        }

        #[ink(message)]
        pub fn initialize(&mut self, initial_root: [u8; 32]) -> Result<(), Error> {
            self.ensure_owner()?;
            
            if self.initialized {
                return Err(Error::NotAuthorized);
            }

            self.commitment_root = initial_root;
            self.encrypted_state = EncryptedState::new().encrypt()?;
            self.initialized = true;

            Ok(())
        }

        #[ink(message)]
        pub fn process_withdrawal(
            &mut self,
            encrypted_request: Vec<u8>,
        ) -> Result<WithdrawalResponse, Error> {
            self.ensure_initialized()?;

            let request = self.decrypt_request(&encrypted_request)?;
            
            self.verify_nullifier_unused(&request.nullifier)?;

            let processor = WithdrawalProcessor::new(
                self.commitment_root,
                self.evm_vault_address,
            );

            let (zk_proof, is_valid) = processor.generate_withdrawal_proof(&request)?;

            if !is_valid {
                return Err(Error::InvalidProof);
            }

            self.nullifier_set.push(request.nullifier);

            let attestation = self.generate_tee_attestation(&request, &zk_proof)?;

            self.log_audit_entry(&request, &zk_proof)?;

            Ok(WithdrawalResponse {
                success: true,
                tx_hash: None,
                zk_proof,
                tee_attestation: attestation,
                error: None,
            })
        }

        #[ink(message)]
        pub fn generate_compliance_proof(
            &self,
            commitment: [u8; 32],
            asp_id: AccountId,
        ) -> Result<ComplianceProof, Error> {
            self.ensure_initialized()?;
            self.ensure_asp_registered(&asp_id)?;

            let association_root = self.get_asp_root(&asp_id)?;

            let zk_proof = self.generate_association_proof(commitment, association_root)?;

            let timestamp = pink::ext().untrusted_millis_since_unix_epoch();

            Ok(ComplianceProof {
                deposit_commitment: commitment,
                association_root,
                zk_proof,
                asp_signature: Vec::new(),
                timestamp,
            })
        }

        #[ink(message)]
        pub fn update_commitment_root(&mut self, new_root: [u8; 32]) -> Result<(), Error> {
            self.ensure_owner()?;
            self.ensure_initialized()?;

            self.commitment_root = new_root;
            Ok(())
        }

        #[ink(message)]
        pub fn register_asp(&mut self, asp: AccountId) -> Result<(), Error> {
            self.ensure_owner()?;
            
            if !self.asp_registry.contains(&asp) {
                self.asp_registry.push(asp);
            }
            
            Ok(())
        }

        #[ink(message)]
        pub fn is_nullifier_used(&self, nullifier: [u8; 32]) -> bool {
            self.nullifier_set.contains(&nullifier)
        }

        #[ink(message)]
        pub fn get_commitment_root(&self) -> [u8; 32] {
            self.commitment_root
        }

        #[ink(message)]
        pub fn get_audit_log_count(&self) -> u32 {
            self.audit_log.len() as u32
        }

        #[ink(message)]
        pub fn get_tee_attestation_report(&self) -> Vec<u8> {
            self.generate_attestation_report()
        }

        fn ensure_owner(&self) -> Result<(), Error> {
            if self.env().caller() != self.owner {
                return Err(Error::NotAuthorized);
            }
            Ok(())
        }

        fn ensure_initialized(&self) -> Result<(), Error> {
            if !self.initialized {
                return Err(Error::StateCorrupted);
            }
            Ok(())
        }

        fn ensure_asp_registered(&self, asp: &AccountId) -> Result<(), Error> {
            if !self.asp_registry.contains(asp) {
                return Err(Error::NotAuthorized);
            }
            Ok(())
        }

        fn decrypt_request(&self, encrypted: &[u8]) -> Result<WithdrawalRequest, Error> {
            let state = EncryptedState::decrypt(&self.encrypted_state)?;
            
            WithdrawalRequest::decode(&mut &encrypted[..])
                .map_err(|_| Error::DecryptionError)
        }

        fn verify_nullifier_unused(&self, nullifier: &[u8; 32]) -> Result<(), Error> {
            if self.nullifier_set.contains(nullifier) {
                return Err(Error::NullifierAlreadyUsed);
            }
            Ok(())
        }

        fn generate_tee_attestation(
            &self,
            request: &WithdrawalRequest,
            proof: &[u8],
        ) -> Result<Vec<u8>, Error> {
            use sha2::{Sha256, Digest};
            
            let mut hasher = Sha256::new();
            hasher.update(&request.commitment);
            hasher.update(&request.nullifier);
            hasher.update(proof);
            hasher.update(&self.commitment_root);
            
            let data_hash = hasher.finalize();
            
            let attestation = AttestationReport {
                data_hash: data_hash.into(),
                timestamp: pink::ext().untrusted_millis_since_unix_epoch(),
                enclave_id: self.get_enclave_id(),
                signature: Vec::new(),
            };
            
            attestation.encode().into()
        }

        fn log_audit_entry(
            &mut self,
            request: &WithdrawalRequest,
            proof: &[u8],
        ) -> Result<(), Error> {
            use sha2::{Sha256, Digest};
            
            let mut hasher = Sha256::new();
            hasher.update(&request.commitment);
            hasher.update(&request.amount.to_le_bytes());
            let entry_hash: [u8; 32] = hasher.finalize().into();
            
            let details = AuditDetails {
                commitment: request.commitment,
                amount: request.amount,
                recipient_hash: self.hash_recipient(&request.recipient),
            };
            
            let encrypted_details = self.encrypt_audit_details(&details)?;
            let attestation = self.generate_attestation_report();
            
            let entry = AuditEntry {
                timestamp: pink::ext().untrusted_millis_since_unix_epoch(),
                entry_hash,
                encrypted_details,
                tee_attestation: attestation,
            };
            
            self.audit_log.push(entry);
            Ok(())
        }

        fn generate_association_proof(
            &self,
            commitment: [u8; 32],
            association_root: [u8; 32],
        ) -> Result<Vec<u8>, Error> {
            let proof_data = AssociationProofData {
                commitment,
                association_root,
                deposit_root: self.commitment_root,
            };
            
            Ok(proof_data.encode())
        }

        fn get_asp_root(&self, _asp: &AccountId) -> Result<[u8; 32], Error> {
            Ok([0u8; 32])
        }

        fn get_enclave_id(&self) -> [u8; 32] {
            let mut id = [0u8; 32];
            id[0..20].copy_from_slice(&self.evm_vault_address);
            id
        }

        fn hash_recipient(&self, recipient: &[u8; 20]) -> [u8; 32] {
            use sha2::{Sha256, Digest};
            let mut hasher = Sha256::new();
            hasher.update(recipient);
            hasher.finalize().into()
        }

        fn encrypt_audit_details(&self, details: &AuditDetails) -> Result<Vec<u8>, Error> {
            Ok(details.encode())
        }

        fn generate_attestation_report(&self) -> Vec<u8> {
            let report = AttestationReport {
                data_hash: self.commitment_root,
                timestamp: pink::ext().untrusted_millis_since_unix_epoch(),
                enclave_id: self.get_enclave_id(),
                signature: Vec::new(),
            };
            report.encode()
        }
    }

    #[derive(Debug, Clone, Encode, Decode)]
    struct AttestationReport {
        data_hash: [u8; 32],
        timestamp: u64,
        enclave_id: [u8; 32],
        signature: Vec<u8>,
    }

    #[derive(Debug, Clone, Encode, Decode)]
    struct AuditDetails {
        commitment: [u8; 32],
        amount: u128,
        recipient_hash: [u8; 32],
    }

    #[derive(Debug, Clone, Encode, Decode)]
    struct AssociationProofData {
        commitment: [u8; 32],
        association_root: [u8; 32],
        deposit_root: [u8; 32],
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use ink::env::test;

        fn default_accounts() -> test::DefaultAccounts<ink::env::DefaultEnvironment> {
            test::default_accounts::<ink::env::DefaultEnvironment>()
        }

        #[ink::test]
        fn test_constructor() {
            let vault = PrivacyVaultTee::new([0xde, 0xad, 0xbe, 0xef, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 1);
            assert!(!vault.initialized);
            assert_eq!(vault.get_audit_log_count(), 0);
        }

        #[ink::test]
        fn test_initialization() {
            let mut vault = PrivacyVaultTee::default();
            let initial_root = [1u8; 32];
            
            let result = vault.initialize(initial_root);
            assert!(result.is_ok());
            assert!(vault.initialized);
            assert_eq!(vault.get_commitment_root(), initial_root);
        }

        #[ink::test]
        fn test_nullifier_tracking() {
            let mut vault = PrivacyVaultTee::default();
            vault.initialize([0u8; 32]).unwrap();
            
            let nullifier = [42u8; 32];
            assert!(!vault.is_nullifier_used(nullifier));
            
            vault.nullifier_set.push(nullifier);
            assert!(vault.is_nullifier_used(nullifier));
        }

        #[ink::test]
        fn test_asp_registration() {
            let mut vault = PrivacyVaultTee::default();
            let accounts = default_accounts();
            
            vault.register_asp(accounts.bob).unwrap();
            assert!(vault.asp_registry.contains(&accounts.bob));
        }
    }
}

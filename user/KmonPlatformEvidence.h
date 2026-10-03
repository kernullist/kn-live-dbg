#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <vector>

struct KmonPlatformEvidenceResult
{
    std::map<std::wstring, std::wstring> Fields;
    std::vector<std::wstring> Warnings;
    // Complete describes local source collection, never platform trust.
    bool Complete = false;
};

struct KmonAttestationRequest
{
    std::vector<uint8_t> Nonce;
    std::string DeviceIdentity;
    std::vector<uint8_t> AttestationKeySha256;
    uint64_t IssuedUnixSeconds = 0;
    uint64_t ExpiresUnixSeconds = 0;
    bool Consumed = false;
};

struct KmonExternalAttestationClaim
{
    std::vector<uint8_t> Nonce;
    std::string DeviceIdentity;
    std::vector<uint8_t> AttestationKeySha256;
    std::vector<uint8_t> Quote;
    uint64_t IssuedUnixSeconds = 0;
    uint64_t ExpiresUnixSeconds = 0;
    // These assertions must come from the configured external verifier.
    bool QuoteVerified = false;
    bool BootStateAccepted = false;
    // ECDSA P-256 signature: 32-byte big-endian r followed by s.
    std::vector<uint8_t> Signature;
};

struct KmonAttestationVerificationResult
{
    bool Trusted = false;
    bool SignatureVerified = false;
    bool QuoteVerifiedLocally = false;
    std::wstring Reason;
};

bool CollectKmonPlatformEvidence(KmonPlatformEvidenceResult* result, std::wstring* error);

// Empty identity/key requests expose a nonce only and can never pass verification.
bool CreateKmonAttestationRequest(const std::string& deviceIdentity,
    const std::vector<uint8_t>& attestationKeySha256, KmonAttestationRequest* request,
    std::wstring* error);

// The public key must be provisioned independently, never supplied by the claim.
// It is a BCRYPT_ECCPUBLIC_BLOB for ECDSA P-256. The caller owns request lifetime
// and serializes verification; successful claims consume the request once.
// This verifies a trusted verifier's signed verdict, not a raw TPM quote.
bool VerifyKmonExternalAttestation(KmonAttestationRequest* request,
    const KmonExternalAttestationClaim& claim,
    const std::vector<uint8_t>& trustedVerifierPublicKeyBlob, uint64_t nowUnixSeconds,
    KmonAttestationVerificationResult* result);

// External verifiers sign SHA-256 of these versioned, length-prefixed bytes.
bool BuildKmonAttestationClaimPayload(const KmonExternalAttestationClaim& claim,
    std::vector<uint8_t>* payload);

bool KmonPlatformEvidenceSelfTest();

{
  "claim_id": "hackathon-final-fortified-007",
  "claim": "The supplied standards evidence jointly supports that (1) public-key digital signatures use a private signing key and a corresponding public verification key; (2) verification depends on the appropriate public key; (3) protecting the signing private key is a security requirement; and (4) signature integrity alone does not remove the separate need to establish trust in the origin of a verifier's public key.",
  "declared_scope": "Only the live-acquired NIST digital-signature, public-key, private-key material and RFC 7515 security material. The Cloud Run documentation is deliberately present in the frozen evidence universe as irrelevant evidence and is not selected for the claim.",
  "evidence_ids": [
    "e1",
    "e2",
    "e3",
    "e4"
  ],
  "atoms": [
    {
      "atom_id": "a1",
      "statement": "In a public-key digital-signature setting, signing uses a private key and verification uses the corresponding public-key mechanism.",
      "evidence_ids": [
        "e1",
        "e4"
      ]
    },
    {
      "atom_id": "a2",
      "statement": "The appropriate public key is part of verifying a public-key digital signature.",
      "evidence_ids": [
        "e2",
        "e4"
      ]
    },
    {
      "atom_id": "a3",
      "statement": "The signing private key is intended to remain protected, and compromise of that key undermines signer assurance.",
      "evidence_ids": [
        "e3",
        "e4"
      ]
    },
    {
      "atom_id": "a4",
      "statement": "Digital signatures can provide integrity and authenticity assurance, while the origin of a public verification key must still be trusted or authenticated separately.",
      "evidence_ids": [
        "e1",
        "e4"
      ]
    }
  ],
  "assurance_profile": "SEMANTIC_FORTIFIED"
}
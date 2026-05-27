package main

import (
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

type SmartContract struct {
	contractapi.Contract
}

type DIDRecord struct {
	DocType         string `json:"docType"`
	DID             string `json:"did"`
	DevicePublicKey string `json:"device_public_key"`
	DIDDocumentHash string `json:"did_document_hash"`
	CreatedAt       string `json:"created_at"`
	Active          bool   `json:"active"`
}

type CredentialStatus struct {
	DocType          string `json:"docType"`
	CredentialID     string `json:"credential_id"`
	CredentialType   string `json:"credential_type"`
	SubjectDID       string `json:"subject_did"`
	Issuer           string `json:"issuer"`
	IssuedAt         string `json:"issued_at"`
	ExpiresAt        string `json:"expires_at"`
	Revoked          bool   `json:"revoked"`
	RevokedAt        string `json:"revoked_at"`
	RevocationReason string `json:"revocation_reason"`
}

func (s *SmartContract) Ping(ctx contractapi.TransactionContextInterface) string {
	return "pong"
}

func (s *SmartContract) RegisterDID(ctx contractapi.TransactionContextInterface, did string, devicePublicKey string, didDocumentHash string, createdAt string) error {
	key := didKey(did)
	existing, err := ctx.GetStub().GetState(key)
	if err != nil {
		return fmt.Errorf("failed to check DID: %w", err)
	}
	if existing != nil {
		return fmt.Errorf("DID already exists: %s", did)
	}

	record := DIDRecord{
		DocType:         "DIDRecord",
		DID:             did,
		DevicePublicKey: devicePublicKey,
		DIDDocumentHash: didDocumentHash,
		CreatedAt:       createdAt,
		Active:          true,
	}
	bytes, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("failed to marshal DID record: %w", err)
	}
	return ctx.GetStub().PutState(key, bytes)
}

func (s *SmartContract) GetDID(ctx contractapi.TransactionContextInterface, did string) (*DIDRecord, error) {
	bytes, err := ctx.GetStub().GetState(didKey(did))
	if err != nil {
		return nil, fmt.Errorf("failed to read DID: %w", err)
	}
	if bytes == nil {
		return nil, fmt.Errorf("DID not found: %s", did)
	}

	var record DIDRecord
	if err := json.Unmarshal(bytes, &record); err != nil {
		return nil, fmt.Errorf("failed to unmarshal DID record: %w", err)
	}
	return &record, nil
}

func (s *SmartContract) DIDExists(ctx contractapi.TransactionContextInterface, did string) (bool, error) {
	bytes, err := ctx.GetStub().GetState(didKey(did))
	if err != nil {
		return false, fmt.Errorf("failed to check DID: %w", err)
	}
	return bytes != nil, nil
}

func (s *SmartContract) RegisterCredentialStatus(ctx contractapi.TransactionContextInterface, credentialID string, credentialType string, subjectDID string, issuer string, issuedAt string, expiresAt string) error {
	key := credentialKey(credentialID)
	existing, err := ctx.GetStub().GetState(key)
	if err != nil {
		return fmt.Errorf("failed to check credential status: %w", err)
	}
	if existing != nil {
		return fmt.Errorf("credential status already exists: %s", credentialID)
	}

	status := CredentialStatus{
		DocType:          "CredentialStatus",
		CredentialID:     credentialID,
		CredentialType:   credentialType,
		SubjectDID:       subjectDID,
		Issuer:           issuer,
		IssuedAt:         issuedAt,
		ExpiresAt:        expiresAt,
		Revoked:          false,
		RevokedAt:        "",
		RevocationReason: "",
	}
	bytes, err := json.Marshal(status)
	if err != nil {
		return fmt.Errorf("failed to marshal credential status: %w", err)
	}
	return ctx.GetStub().PutState(key, bytes)
}

func (s *SmartContract) GetCredentialStatus(ctx contractapi.TransactionContextInterface, credentialID string) (*CredentialStatus, error) {
	bytes, err := ctx.GetStub().GetState(credentialKey(credentialID))
	if err != nil {
		return nil, fmt.Errorf("failed to read credential status: %w", err)
	}
	if bytes == nil {
		return nil, fmt.Errorf("credential status not found: %s", credentialID)
	}

	var status CredentialStatus
	if err := json.Unmarshal(bytes, &status); err != nil {
		return nil, fmt.Errorf("failed to unmarshal credential status: %w", err)
	}
	return &status, nil
}

func (s *SmartContract) RevokeCredential(ctx contractapi.TransactionContextInterface, credentialID string, reason string, revokedAt string) error {
	status, err := s.GetCredentialStatus(ctx, credentialID)
	if err != nil {
		return err
	}
	if status.Revoked {
		return nil
	}

	status.Revoked = true
	status.RevokedAt = revokedAt
	status.RevocationReason = reason

	bytes, err := json.Marshal(status)
	if err != nil {
		return fmt.Errorf("failed to marshal credential status: %w", err)
	}
	return ctx.GetStub().PutState(credentialKey(credentialID), bytes)
}

func (s *SmartContract) IsCredentialRevoked(ctx contractapi.TransactionContextInterface, credentialID string) (bool, error) {
	status, err := s.GetCredentialStatus(ctx, credentialID)
	if err != nil {
		return false, err
	}
	return status.Revoked, nil
}

func (s *SmartContract) ListByPrefix(ctx contractapi.TransactionContextInterface, prefix string, limit string) ([]string, error) {
	limitInt, err := strconv.Atoi(limit)
	if err != nil || limitInt < 1 {
		return nil, fmt.Errorf("limit must be a positive integer")
	}

	results, err := ctx.GetStub().GetStateByRange(prefix, prefix+"\uffff")
	if err != nil {
		return nil, fmt.Errorf("failed to list by prefix: %w", err)
	}
	defer results.Close()

	records := []string{}
	for results.HasNext() && len(records) < limitInt {
		item, err := results.Next()
		if err != nil {
			return nil, fmt.Errorf("failed to read iterator: %w", err)
		}
		records = append(records, string(item.Value))
	}
	return records, nil
}

func didKey(did string) string {
	return "DID::" + did
}

func credentialKey(credentialID string) string {
	return "CRED::" + credentialID
}

func main() {
	chaincode, err := contractapi.NewChaincode(&SmartContract{})
	if err != nil {
		panic(fmt.Sprintf("failed to create IAM chaincode: %v", err))
	}
	if err := chaincode.Start(); err != nil {
		panic(fmt.Sprintf("failed to start IAM chaincode: %v", err))
	}
}

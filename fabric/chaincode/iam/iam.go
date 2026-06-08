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

type AuditEvent struct {
	DocType      string                 `json:"docType"`
	EventID      string                 `json:"event_id"`
	EventType    string                 `json:"event_type"`
	SubjectDID   string                 `json:"subject_did"`
	CredentialID string                 `json:"credential_id"`
	Decision     string                 `json:"decision"`
	Reason       string                 `json:"reason"`
	CreatedAt    string                 `json:"created_at"`
	Service      string                 `json:"service"`
	Metadata     map[string]interface{} `json:"metadata"`
}

type AccumulatorStateRecord struct {
	DocType       string `json:"docType"`
	AccumulatorID string `json:"accumulator_id"`
	Version       int    `json:"version"`
	Root          string `json:"root"`
	Algorithm     string `json:"algorithm"`
	ActiveCount   int    `json:"active_count"`
	RevokedCount  int    `json:"revoked_count"`
	UpdatedAt     string `json:"updated_at"`
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

func (s *SmartContract) AddAuditEvent(ctx contractapi.TransactionContextInterface, eventJson string) error {
	var event AuditEvent
	if err := json.Unmarshal([]byte(eventJson), &event); err != nil {
		return fmt.Errorf("failed to unmarshal audit event: %w", err)
	}
	if event.EventID == "" {
		return fmt.Errorf("event_id is required")
	}
	if event.EventType == "" {
		return fmt.Errorf("event_type is required")
	}
	if event.CreatedAt == "" {
		return fmt.Errorf("created_at is required")
	}
	if event.Service == "" {
		return fmt.Errorf("service is required")
	}

	event.DocType = "AuditEvent"
	if event.Metadata == nil {
		event.Metadata = map[string]interface{}{}
	}

	key := auditKey(event.CreatedAt, event.EventID)
	existing, err := ctx.GetStub().GetState(key)
	if err != nil {
		return fmt.Errorf("failed to check audit event: %w", err)
	}
	if existing != nil {
		return fmt.Errorf("audit event already exists: %s", key)
	}

	bytes, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal audit event: %w", err)
	}
	return ctx.GetStub().PutState(key, bytes)
}

func (s *SmartContract) GetAuditEvent(ctx contractapi.TransactionContextInterface, key string) (*AuditEvent, error) {
	bytes, err := ctx.GetStub().GetState(key)
	if err != nil {
		return nil, fmt.Errorf("failed to read audit event: %w", err)
	}
	if bytes == nil {
		return nil, fmt.Errorf("audit event not found: %s", key)
	}

	var event AuditEvent
	if err := json.Unmarshal(bytes, &event); err != nil {
		return nil, fmt.Errorf("failed to unmarshal audit event: %w", err)
	}
	return &event, nil
}

func (s *SmartContract) ListAuditEvents(ctx contractapi.TransactionContextInterface, limit string) ([]AuditEvent, error) {
	limitInt, err := strconv.Atoi(limit)
	if err != nil || limitInt < 1 {
		return nil, fmt.Errorf("limit must be a positive integer")
	}

	results, err := ctx.GetStub().GetStateByRange("AUDIT::", "AUDIT::\uffff")
	if err != nil {
		return nil, fmt.Errorf("failed to list audit events: %w", err)
	}
	defer results.Close()

	all := []AuditEvent{}
	for results.HasNext() {
		item, err := results.Next()
		if err != nil {
			return nil, fmt.Errorf("failed to read iterator: %w", err)
		}
		var event AuditEvent
		if err := json.Unmarshal(item.Value, &event); err != nil {
			return nil, fmt.Errorf("failed to unmarshal audit event: %w", err)
		}
		all = append(all, event)
	}

	events := []AuditEvent{}
	for index := len(all) - 1; index >= 0 && len(events) < limitInt; index-- {
		events = append(events, all[index])
	}
	return events, nil
}

func (s *SmartContract) PutAccumulatorState(ctx contractapi.TransactionContextInterface, stateJson string) error {
	var state AccumulatorStateRecord
	if err := json.Unmarshal([]byte(stateJson), &state); err != nil {
		return fmt.Errorf("failed to unmarshal accumulator state: %w", err)
	}
	if state.AccumulatorID == "" {
		return fmt.Errorf("accumulator_id is required")
	}
	if state.Root == "" {
		return fmt.Errorf("root is required")
	}
	if state.Algorithm == "" {
		return fmt.Errorf("algorithm is required")
	}
	if state.UpdatedAt == "" {
		return fmt.Errorf("updated_at is required")
	}

	state.DocType = "AccumulatorState"
	bytes, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("failed to marshal accumulator state: %w", err)
	}
	return ctx.GetStub().PutState(accumulatorStateKey(state.AccumulatorID, state.Version), bytes)
}

func (s *SmartContract) GetAccumulatorState(ctx contractapi.TransactionContextInterface, accumulatorID string) (*AccumulatorStateRecord, error) {
	if accumulatorID == "" {
		return nil, fmt.Errorf("accumulator_id is required")
	}
	states, err := s.listAccumulatorStateRecords(ctx, accumulatorID, 1)
	if err != nil {
		return nil, err
	}
	if len(states) == 0 {
		return nil, fmt.Errorf("accumulator state not found: %s", accumulatorID)
	}
	return &states[0], nil
}

func (s *SmartContract) ListAccumulatorStates(ctx contractapi.TransactionContextInterface, limit string) ([]AccumulatorStateRecord, error) {
	limitInt, err := strconv.Atoi(limit)
	if err != nil || limitInt < 1 {
		return nil, fmt.Errorf("limit must be a positive integer")
	}
	return s.listAccumulatorStateRecords(ctx, "", limitInt)
}

func (s *SmartContract) listAccumulatorStateRecords(ctx contractapi.TransactionContextInterface, accumulatorID string, limitInt int) ([]AccumulatorStateRecord, error) {
	prefix := "ACCUMULATOR::"
	if accumulatorID != "" {
		prefix = "ACCUMULATOR::" + accumulatorID + "::"
	}
	results, err := ctx.GetStub().GetStateByRange(prefix, prefix+"\uffff")
	if err != nil {
		return nil, fmt.Errorf("failed to list accumulator states: %w", err)
	}
	defer results.Close()

	all := []AccumulatorStateRecord{}
	for results.HasNext() {
		item, err := results.Next()
		if err != nil {
			return nil, fmt.Errorf("failed to read iterator: %w", err)
		}
		var state AccumulatorStateRecord
		if err := json.Unmarshal(item.Value, &state); err != nil {
			return nil, fmt.Errorf("failed to unmarshal accumulator state: %w", err)
		}
		all = append(all, state)
	}

	states := []AccumulatorStateRecord{}
	for index := len(all) - 1; index >= 0 && len(states) < limitInt; index-- {
		states = append(states, all[index])
	}
	return states, nil
}

func didKey(did string) string {
	return "DID::" + did
}

func credentialKey(credentialID string) string {
	return "CRED::" + credentialID
}

func auditKey(createdAt string, eventID string) string {
	return "AUDIT::" + createdAt + "::" + eventID
}

func accumulatorStateKey(accumulatorID string, version int) string {
	return fmt.Sprintf("ACCUMULATOR::%s::%020d", accumulatorID, version)
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

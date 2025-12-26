package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/elliottech/lighter-go/client"
	httpClient "github.com/elliottech/lighter-go/client/http"
	"github.com/elliottech/lighter-go/types"
	"github.com/elliottech/lighter-go/types/txtypes"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"gopkg.in/yaml.v3"
)

const (
	BaseURL     = "https://mainnet.zklighter.elliot.ai"
	ChainID     = 304 // Mainnet chain ID
	APIName     = "lt28"
	APIKeyIndex = uint8(26) // Override api_key_index to 26
)

// APIConfig represents the configuration for an API in the YAML file
type APIConfig struct {
	ExchangeName string `yaml:"exchange_name"`
	APIKey       string `yaml:"api_key"`
	APISecret    string `yaml:"api_secret"`
	BindIP       string `yaml:"bind_ip"`
	More         struct {
		AccountIndex  int64  `yaml:"account_index"`
		SignerDirPath string `yaml:"signer_dir_path"`
		APIKeyIndex   uint8  `yaml:"api_key_index"`
	} `yaml:"more"`
}

// LighterKey represents a stored L2 private key
type LighterKey struct {
	ID           int64     `json:"id"`
	Timestamp    time.Time `json:"timestamp"`
	APIName      string    `json:"api_name"`
	L2PrivateKey string    `json:"l2_private_key"`
	L2PublicKey  string    `json:"l2_public_key"`
	Nonce        int64     `json:"nonce"`
	APIKeyIndex  uint8     `json:"api_key_index"`
	AccountIndex int64     `json:"account_index"`
}

// KeyDatabase represents the JSON-based key storage
type KeyDatabase struct {
	Keys       []LighterKey `json:"keys"`
	NextID     int64        `json:"next_id"`
	LastUpdate time.Time    `json:"last_update"`
}

func main() {
	fmt.Println("=== L2 Key Setup for Lighter Protocol ===")

	// Check command line arguments
	register := false
	if len(os.Args) > 1 && os.Args[1] == "--register" {
		register = true
		fmt.Println("Mode: Register on-chain (requires Ethereum private key)")
	} else {
		fmt.Println("Mode: Generate L2 key only (no on-chain registration)")
		fmt.Println("To register on-chain, run: go run examples/create_l2_key.go --register")
	}

	// Load API credentials from ~/.rapid/apis/apis_lighter.yaml
	apiConfig, err := loadAPIConfig(APIName)
	if err != nil {
		log.Fatalf("Failed to load API config: %v", err)
	}

	accountIndex := apiConfig.More.AccountIndex
	ethPrivateKey := apiConfig.APISecret

	fmt.Printf("\nAPI Name: %s\n", APIName)
	fmt.Printf("Account Index: %d\n", accountIndex)
	fmt.Printf("API Key Index: %d (overridden)\n", APIKeyIndex)

	// Check if L2 key already exists
	existingKey, err := getL2Key(APIName, APIKeyIndex, accountIndex)
	if err == nil && !register {
		fmt.Printf("\nL2 key already exists for %s (account=%d, key_index=%d)\n",
			APIName, accountIndex, APIKeyIndex)
		fmt.Printf("  Private Key: %.20s...\n", existingKey.L2PrivateKey)
		fmt.Printf("  Public Key: %.20s...\n", existingKey.L2PublicKey)
		fmt.Println("\nTo register this key on-chain, run: go run examples/create_l2_key.go --register")
		return
	}

	// Generate a new L2 key pair or use existing
	var l2PrivateKey, l2PublicKey string

	if existingKey != nil {
		// Use existing key for registration
		l2PrivateKey = existingKey.L2PrivateKey
		l2PublicKey = existingKey.L2PublicKey
		fmt.Printf("\nUsing existing L2 key for registration\n")
	} else {
		// Generate new key
		fmt.Println("\n=== Generating L2 Key Pair ===")
		l2PrivateKey, l2PublicKey, err = client.GenerateAPIKey()
		if err != nil {
			log.Fatalf("Failed to generate L2 key: %v", err)
		}
		fmt.Println("New L2 key pair generated!")
	}

	fmt.Printf("\nL2 Private Key: %s\n", l2PrivateKey)
	fmt.Printf("L2 Public Key:  %s\n", l2PublicKey)

	// Save to ~/.rapid/keys.json
	err = saveL2Key(APIName, l2PrivateKey, l2PublicKey, -1, APIKeyIndex, accountIndex)
	if err != nil {
		log.Fatalf("Failed to save L2 key: %v", err)
	}
	fmt.Println("\nL2 key saved to ~/.rapid/keys.json")

	if !register {
		fmt.Println("\n=== Setup Complete (Local Only) ===")
		fmt.Println("L2 key generated and saved!")
		fmt.Println("\nTo register on-chain, run: go run examples/create_l2_key.go --register")
		return
	}

	// Register on-chain
	fmt.Println("\n=== Registering L2 Key On-Chain ===")

	err = registerL2Key(ethPrivateKey, l2PrivateKey, l2PublicKey, accountIndex, APIKeyIndex)
	if err != nil {
		log.Fatalf("Failed to register L2 key: %v", err)
	}

	fmt.Println("\n=== Registration Complete ===")
	fmt.Println("Your L2 key is now registered on Lighter!")
}

// loadAPIConfig loads API configuration from ~/.rapid/apis/apis_lighter.yaml
func loadAPIConfig(apiName string) (*APIConfig, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get home directory: %w", err)
	}

	configPath := filepath.Join(homeDir, ".rapid", "apis", "apis_lighter.yaml")

	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file %s: %w", configPath, err)
	}

	var configs map[string]*APIConfig
	if err := yaml.Unmarshal(data, &configs); err != nil {
		return nil, fmt.Errorf("failed to parse YAML config: %w", err)
	}

	config, exists := configs[apiName]
	if !exists {
		return nil, fmt.Errorf("API configuration '%s' not found in %s", apiName, configPath)
	}

	return config, nil
}

// getKeysDBPath returns the path to the JSON database file
func getKeysDBPath() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get home directory: %w", err)
	}

	rapidDir := filepath.Join(homeDir, ".rapid")
	if err := os.MkdirAll(rapidDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create .rapid directory: %w", err)
	}

	return filepath.Join(rapidDir, "keys.json"), nil
}

// loadDatabase loads the key database from JSON file
func loadDatabase() (*KeyDatabase, error) {
	dbPath, err := getKeysDBPath()
	if err != nil {
		return nil, err
	}

	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		return &KeyDatabase{
			Keys:       []LighterKey{},
			NextID:     1,
			LastUpdate: time.Now(),
		}, nil
	}

	data, err := os.ReadFile(dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read database file: %w", err)
	}

	var db KeyDatabase
	if err := json.Unmarshal(data, &db); err != nil {
		return nil, fmt.Errorf("failed to parse database: %w", err)
	}

	return &db, nil
}

// saveDatabase saves the key database to JSON file
func saveDatabase(db *KeyDatabase) error {
	dbPath, err := getKeysDBPath()
	if err != nil {
		return err
	}

	db.LastUpdate = time.Now()

	data, err := json.MarshalIndent(db, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal database: %w", err)
	}

	tempPath := dbPath + ".tmp"
	if err := os.WriteFile(tempPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write database file: %w", err)
	}

	if err := os.Rename(tempPath, dbPath); err != nil {
		return fmt.Errorf("failed to save database: %w", err)
	}

	return nil
}

// saveL2Key saves an L2 private key to the database
func saveL2Key(apiName, l2PrivateKey, l2PublicKey string, nonce int64, apiKeyIndex uint8, accountIndex int64) error {
	db, err := loadDatabase()
	if err != nil {
		return err
	}

	// Check if key already exists and update it
	found := false
	for i, key := range db.Keys {
		if key.APIName == apiName && key.APIKeyIndex == apiKeyIndex && key.AccountIndex == accountIndex {
			db.Keys[i].L2PrivateKey = l2PrivateKey
			db.Keys[i].L2PublicKey = l2PublicKey
			db.Keys[i].Nonce = nonce
			db.Keys[i].Timestamp = time.Now()
			found = true
			break
		}
	}

	if !found {
		newKey := LighterKey{
			ID:           db.NextID,
			Timestamp:    time.Now(),
			APIName:      apiName,
			L2PrivateKey: l2PrivateKey,
			L2PublicKey:  l2PublicKey,
			Nonce:        nonce,
			APIKeyIndex:  apiKeyIndex,
			AccountIndex: accountIndex,
		}
		db.Keys = append(db.Keys, newKey)
		db.NextID++
	}

	return saveDatabase(db)
}

// getL2Key retrieves an L2 key from the database
func getL2Key(apiName string, apiKeyIndex uint8, accountIndex int64) (*LighterKey, error) {
	db, err := loadDatabase()
	if err != nil {
		return nil, err
	}

	for i := range db.Keys {
		key := &db.Keys[i]
		if key.APIName == apiName && key.APIKeyIndex == apiKeyIndex && key.AccountIndex == accountIndex {
			return key, nil
		}
	}

	return nil, fmt.Errorf("no L2 key found for api_name=%s, api_key_index=%d, account_index=%d", apiName, apiKeyIndex, accountIndex)
}

// registerL2Key registers the L2 public key on-chain
func registerL2Key(ethPrivateKey, l2PrivateKey, l2PublicKey string, accountIndex int64, apiKeyIndex uint8) error {
	// Create HTTP client and TxClient with the NEW L2 key
	httpCli := httpClient.NewClient(BaseURL)
	txClient, err := client.CreateClient(httpCli, l2PrivateKey, ChainID, apiKeyIndex, accountIndex)
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}

	// Get the public key bytes for ChangePubKey request
	pubKeyBytes := txClient.GetKeyManager().PubKeyBytes()
	var pubKey [40]byte
	copy(pubKey[:], pubKeyBytes[:])

	// Create the ChangePubKey transaction
	changePubKeyReq := &types.ChangePubKeyReq{
		PubKey: pubKey,
	}

	// Get signed ChangePubKey transaction (this signs with L2 key)
	signedTx, err := txClient.GetChangePubKeyTransaction(changePubKeyReq, nil)
	if err != nil {
		return fmt.Errorf("failed to create ChangePubKey transaction: %w", err)
	}

	// Now we need to add the L1 (Ethereum) signature
	l1SignatureBody := signedTx.GetL1SignatureBody()
	fmt.Printf("L1 Signature Body: %s\n", l1SignatureBody)

	// Sign with Ethereum key
	l1Sig, err := signEthereumMessage(ethPrivateKey, l1SignatureBody)
	if err != nil {
		return fmt.Errorf("failed to sign with Ethereum key: %w", err)
	}
	signedTx.L1Sig = l1Sig
	fmt.Printf("L1 Signature: %.40s...\n", l1Sig)

	// Send the transaction
	fmt.Println("\nSending ChangePubKey transaction...")
	txHash, err := sendRawTx(signedTx)
	if err != nil {
		if strings.Contains(err.Error(), "already registered") {
			fmt.Println("L2 key is already registered on-chain")
			return nil
		}
		return fmt.Errorf("failed to send transaction: %w", err)
	}

	fmt.Printf("Transaction sent! Hash: %s\n", txHash)
	fmt.Println("Waiting for confirmation...")

	time.Sleep(3 * time.Second)

	fmt.Println("Verifying registration...")
	if err := txClient.Check(); err != nil {
		fmt.Printf("Warning: Verification failed (may need more time): %v\n", err)
	} else {
		fmt.Println("L2 key successfully verified on-chain!")
	}

	return nil
}

// signEthereumMessage signs a message using Ethereum private key (EIP-191 personal sign)
func signEthereumMessage(privateKeyHex, message string) (string, error) {
	if len(privateKeyHex) >= 2 && privateKeyHex[:2] == "0x" {
		privateKeyHex = privateKeyHex[2:]
	}

	privateKey, err := crypto.HexToECDSA(privateKeyHex)
	if err != nil {
		return "", fmt.Errorf("failed to parse private key: %w", err)
	}

	messageHash := accounts.TextHash([]byte(message))

	signature, err := crypto.Sign(messageHash, privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign message: %w", err)
	}

	if signature[64] < 27 {
		signature[64] += 27
	}

	return hexutil.Encode(signature), nil
}

// sendRawTx sends a signed transaction to Lighter
func sendRawTx(tx txtypes.TxInfo) (string, error) {
	txType := tx.GetTxType()
	txInfo, err := tx.GetTxInfo()
	if err != nil {
		return "", fmt.Errorf("failed to get transaction info: %w", err)
	}

	data := url.Values{}
	data.Set("tx_type", fmt.Sprintf("%d", txType))
	data.Set("tx_info", txInfo)

	req, err := http.NewRequest("POST", BaseURL+"/api/v1/sendTx", strings.NewReader(data.Encode()))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("user-agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36")

	httpCli := &http.Client{Timeout: 30 * time.Second}
	resp, err := httpCli.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to send transaction: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var errorResp struct {
			Code    int32  `json:"code"`
			Message string `json:"message"`
		}
		if json.Unmarshal(body, &errorResp) == nil && errorResp.Message != "" {
			return "", fmt.Errorf("API error %d: %s", errorResp.Code, errorResp.Message)
		}
		return "", fmt.Errorf("HTTP error %s: %s", resp.Status, string(body))
	}

	var result struct {
		Code   int32  `json:"code"`
		TxHash string `json:"tx_hash,omitempty"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return tx.GetTxHash(), nil
	}

	if result.TxHash != "" {
		return result.TxHash, nil
	}

	return tx.GetTxHash(), nil
}

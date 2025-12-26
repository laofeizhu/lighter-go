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
	"gopkg.in/yaml.v3"
)

const (
	BaseURL     = "https://mainnet.zklighter.elliot.ai"
	ChainID     = 304 // Mainnet chain ID
	APIName     = "lt28"
	APIKeyIndex = uint8(26)
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
	fmt.Println("=== Lighter Go Order Example ===")

	// Load API credentials from ~/.rapid/apis/apis_lighter.yaml
	apiConfig, err := loadAPIConfig(APIName)
	if err != nil {
		log.Fatalf("Failed to load API config: %v", err)
	}

	accountIndex := apiConfig.More.AccountIndex

	fmt.Printf("API Name: %s\n", APIName)
	fmt.Printf("Account Index: %d\n", accountIndex)
	fmt.Printf("API Key Index: %d\n", APIKeyIndex)

	// Load L2 key from ~/.rapid/keys.json
	l2Key, err := getL2Key(APIName, APIKeyIndex, accountIndex)
	if err != nil {
		log.Fatalf("Failed to load L2 key: %v\nRun 'go run examples/create_l2_key.go' first to generate a key", err)
	}

	fmt.Printf("L2 Private Key: %.20s...\n", l2Key.L2PrivateKey)

	// Create HTTP client
	httpCli := httpClient.NewClient(BaseURL)

	// Create TxClient
	txClient, err := client.CreateClient(httpCli, l2Key.L2PrivateKey, ChainID, APIKeyIndex, accountIndex)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	// Verify the client's public key matches what's registered on Lighter
	if err := txClient.Check(); err != nil {
		log.Fatalf("Client check failed: %v\nMake sure the L2 key is registered on-chain. Run 'go run examples/create_l2_key.go --register'", err)
	}
	fmt.Println("Client created and verified!")

	// Create a limit order
	fmt.Println("\n=== Creating Limit Order ===")
	fmt.Println("Note: Using a far-from-market price for safety")

	orderReq := &types.CreateOrderTxReq{
		MarketIndex:      0,      // ETH/USD
		ClientOrderIndex: 123,    // Your order ID
		BaseAmount:       1000, // Amount in base units
		Price:            406000, // Price (far from market for safety)
		IsAsk:            1,      // 1 = sell, 0 = buy
		Type:             txtypes.LimitOrder,
		TimeInForce:      txtypes.GoodTillTime,
		ReduceOnly:       0,
		TriggerPrice:     0,
		OrderExpiry:      time.Now().Add(28 * 24 * time.Hour).UnixMilli(),
	}

	// Sign the order (nonce is fetched automatically)
	signedOrder, err := txClient.GetCreateOrderTransaction(orderReq, nil)
	if err != nil {
		log.Fatalf("Failed to sign order: %v", err)
	}

	fmt.Printf("Order signed! TxHash: %s\n", signedOrder.GetTxHash())

	// Send the order
	txHash, err := sendRawTx(signedOrder)
	if err != nil {
		log.Fatalf("Failed to send order: %v", err)
	}

	fmt.Printf("Order sent! TxHash: %s\n", txHash)

	// Wait before canceling
	fmt.Println("\n=== Waiting 3 seconds before canceling ===")
	time.Sleep(3 * time.Second)

	// Cancel the order
	fmt.Println("\n=== Canceling Order ===")

	cancelReq := &types.CancelOrderTxReq{
		MarketIndex: 0,
		Index:       123, // Same as ClientOrderIndex
	}

	signedCancel, err := txClient.GetCancelOrderTransaction(cancelReq, nil)
	if err != nil {
		log.Fatalf("Failed to sign cancel: %v", err)
	}

	cancelTxHash, err := sendRawTx(signedCancel)
	if err != nil {
		log.Fatalf("Failed to send cancel: %v", err)
	}

	fmt.Printf("Order canceled! TxHash: %s\n", cancelTxHash)
	fmt.Println("\n=== Example Complete ===")
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

	return filepath.Join(homeDir, ".rapid", "keys.json"), nil
}

// loadDatabase loads the key database from JSON file
func loadDatabase() (*KeyDatabase, error) {
	dbPath, err := getKeysDBPath()
	if err != nil {
		return nil, err
	}

	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("keys database not found at %s", dbPath)
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

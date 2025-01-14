package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"log"
	"time"

	"github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/frodo/frodo640shake"
	"github.com/cloudflare/circl/kem/kyber/kyber1024"
	"github.com/cloudflare/circl/kem/kyber/kyber512"
	"github.com/cloudflare/circl/kem/kyber/kyber768"
	"github.com/cloudflare/circl/sign"
	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

// RepeatedBenchmarkKEM runs a KEM scheme multiple times to get average, min, and max metrics.
func RepeatedBenchmarkKEM(schemeName string, scheme kem.Scheme, numRuns int) {
	var totalKeyGen, totalEnc, totalDec time.Duration
	minKeyGen := time.Duration(1 << 63 - 1)
	minEnc := time.Duration(1 << 63 - 1)
	minDec := time.Duration(1 << 63 - 1)
	maxKeyGen := time.Duration(0)
	maxEnc := time.Duration(0)
	maxDec := time.Duration(0)

	fmt.Printf("\n==== Repeated Benchmarking KEM: %s ====\n", schemeName)

	for i := 0; i < numRuns; i++ {
		// Key Generation
		start := time.Now()
		publicKey, privateKey, err := scheme.GenerateKeyPair()
		if err != nil {
			log.Fatalf("Key generation error for %s: %v", schemeName, err)
		}
		keyGenTime := time.Since(start)

		// Update stats
		totalKeyGen += keyGenTime
		if keyGenTime < minKeyGen {
			minKeyGen = keyGenTime
		}
		if keyGenTime > maxKeyGen {
			maxKeyGen = keyGenTime
		}

		// Encapsulation
		start = time.Now()
		ciphertext, sharedSecretEnc, err := scheme.Encapsulate(publicKey)
		if err != nil {
			log.Fatalf("Encapsulation error for %s: %v", schemeName, err)
		}
		encTime := time.Since(start)

		// Update stats
		totalEnc += encTime
		if encTime < minEnc {
			minEnc = encTime
		}
		if encTime > maxEnc {
			maxEnc = encTime
		}

		// Decapsulation
		start = time.Now()
		sharedSecretDec, err := scheme.Decapsulate(privateKey, ciphertext)
		if err != nil {
			log.Fatalf("Decapsulation error for %s: %v", schemeName, err)
		}
		decTime := time.Since(start)

		// Update stats
		totalDec += decTime
		if decTime < minDec {
			minDec = decTime
		}
		if decTime > maxDec {
			maxDec = decTime
		}

		// Verify Shared Secrets
		if !bytes.Equal(sharedSecretEnc, sharedSecretDec) {
			fmt.Printf("Run #%d: Shared secrets do NOT match for %s!\n", i+1, schemeName)
		}
	}

	// Compute averages
	avgKeyGen := totalKeyGen / time.Duration(numRuns)
	avgEnc := totalEnc / time.Duration(numRuns)
	avgDec := totalDec / time.Duration(numRuns)

	fmt.Printf("After %d runs:\n", numRuns)
	fmt.Printf("Key Generation: avg=%v, min=%v, max=%v\n", avgKeyGen, minKeyGen, maxKeyGen)
	fmt.Printf("Encapsulation:  avg=%v, min=%v, max=%v\n", avgEnc, minEnc, maxEnc)
	fmt.Printf("Decapsulation:  avg=%v, min=%v, max=%v\n", avgDec, minDec, maxDec)
	fmt.Println("-----------------------------------")
}

// RepeatedBenchmarkSignature runs a signature scheme multiple times to get average, min, and max metrics.
func RepeatedBenchmarkSignature(schemeName string, scheme sign.Scheme, numRuns int) {
	var totalKeyGen, totalSign, totalVerify time.Duration
	minKeyGen := time.Duration(1 << 63 - 1)
	minSign := time.Duration(1 << 63 - 1)
	minVerify := time.Duration(1 << 63 - 1)
	maxKeyGen := time.Duration(0)
	maxSign := time.Duration(0)
	maxVerify := time.Duration(0)

	fmt.Printf("\n==== Repeated Benchmarking Signature: %s ====\n", schemeName)

	message := []byte("This is a test message.")
	ctx := []byte("context") // optional context

	for i := 0; i < numRuns; i++ {
		// Key Generation
		start := time.Now()
		publicKey, privateKey, err := scheme.GenerateKey()
		if err != nil {
			log.Fatalf("Key generation error for %s: %v", schemeName, err)
		}
		keyGenTime := time.Since(start)

		// Update stats
		totalKeyGen += keyGenTime
		if keyGenTime < minKeyGen {
			minKeyGen = keyGenTime
		}
		if keyGenTime > maxKeyGen {
			maxKeyGen = keyGenTime
		}

		// Signing
		signature := make([]byte, scheme.SignatureSize())
		start = time.Now()

		switch sk := privateKey.(type) {
		case *mldsa44.PrivateKey:
			err = mldsa44.SignTo(sk, message, ctx, false, signature)
		case *mldsa65.PrivateKey:
			err = mldsa65.SignTo(sk, message, ctx, false, signature)
		case *mldsa87.PrivateKey:
			err = mldsa87.SignTo(sk, message, ctx, false, signature)
		default:
			log.Fatalf("Unsupported private key type for %s", schemeName)
		}
		if err != nil {
			log.Fatalf("Signing error for %s: %v", schemeName, err)
		}
		signTime := time.Since(start)

		// Update stats
		totalSign += signTime
		if signTime < minSign {
			minSign = signTime
		}
		if signTime > maxSign {
			maxSign = signTime
		}

		// Verification
		start = time.Now()
		var valid bool
		switch pk := publicKey.(type) {
		case *mldsa44.PublicKey:
			valid = mldsa44.Verify(pk, message, ctx, signature)
		case *mldsa65.PublicKey:
			valid = mldsa65.Verify(pk, message, ctx, signature)
		case *mldsa87.PublicKey:
			valid = mldsa87.Verify(pk, message, ctx, signature)
		default:
			log.Fatalf("Unsupported public key type for %s", schemeName)
		}
		verifyTime := time.Since(start)

		// Update stats
		totalVerify += verifyTime
		if verifyTime < minVerify {
			minVerify = verifyTime
		}
		if verifyTime > maxVerify {
			maxVerify = verifyTime
		}

		if !valid {
			fmt.Printf("Run #%d: Signature verification FAILED for %s!\n", i+1, schemeName)
		}
	}

	// Compute averages
	avgKeyGen := totalKeyGen / time.Duration(numRuns)
	avgSign := totalSign / time.Duration(numRuns)
	avgVerify := totalVerify / time.Duration(numRuns)

	fmt.Printf("After %d runs:\n", numRuns)
	fmt.Printf("Key Generation: avg=%v, min=%v, max=%v\n", avgKeyGen, minKeyGen, maxKeyGen)
	fmt.Printf("Signing:        avg=%v, min=%v, max=%v\n", avgSign, minSign, maxSign)
	fmt.Printf("Verification:   avg=%v, min=%v, max=%v\n", avgVerify, minVerify, maxVerify)
	fmt.Println("-----------------------------------")
}

// BenchmarkRSA demonstrates a quick comparison with an RSA-2048 key generation and encryption/decryption.
func BenchmarkRSA(numRuns int) {
	fmt.Println("\n==== Benchmarking Traditional RSA-2048 ====")

	var totalKeyGen, totalEnc, totalDec time.Duration
	minKeyGen := time.Duration(1 << 63 - 1)
	minEnc := time.Duration(1 << 63 - 1)
	minDec := time.Duration(1 << 63 - 1)
	maxKeyGen := time.Duration(0)
	maxEnc := time.Duration(0)
	maxDec := time.Duration(0)

	message := []byte("This is a test message for RSA")

	for i := 0; i < numRuns; i++ {
		// Key Generation
		start := time.Now()
		privKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			log.Fatalf("RSA key gen error: %v", err)
		}
		keyGenTime := time.Since(start)
		totalKeyGen += keyGenTime
		if keyGenTime < minKeyGen {
			minKeyGen = keyGenTime
		}
		if keyGenTime > maxKeyGen {
			maxKeyGen = keyGenTime
		}

		// Encryption
		start = time.Now()
		ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &privKey.PublicKey, message, nil)
		if err != nil {
			log.Fatalf("RSA encryption error: %v", err)
		}
		encTime := time.Since(start)
		totalEnc += encTime
		if encTime < minEnc {
			minEnc = encTime
		}
		if encTime > maxEnc {
			maxEnc = encTime
		}

		// Decryption
		start = time.Now()
		plaintext, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privKey, ciphertext, nil)
		if err != nil {
			log.Fatalf("RSA decryption error: %v", err)
		}
		decTime := time.Since(start)
		totalDec += decTime
		if decTime < minDec {
			minDec = decTime
		}
		if decTime > maxDec {
			maxDec = decTime
		}

		// Basic check
		if !bytes.Equal(plaintext, message) {
			fmt.Printf("Run #%d: RSA plaintext mismatch!\n", i+1)
		}
	}

	avgKeyGen := totalKeyGen / time.Duration(numRuns)
	avgEnc := totalEnc / time.Duration(numRuns)
	avgDec := totalDec / time.Duration(numRuns)

	fmt.Printf("After %d runs (RSA-2048):\n", numRuns)
	fmt.Printf("Key Generation: avg=%v, min=%v, max=%v\n", avgKeyGen, minKeyGen, maxKeyGen)
	fmt.Printf("Encryption:     avg=%v, min=%v, max=%v\n", avgEnc, minEnc, maxEnc)
	fmt.Printf("Decryption:     avg=%v, min=%v, max=%v\n", avgDec, minDec, maxDec)
	fmt.Println("-----------------------------------")
}

// BenchmarkECDSA quickly compares an ECDSA P-256 signature scheme.
func BenchmarkECDSA(numRuns int) {
	fmt.Println("\n==== Benchmarking Traditional ECDSA (P-256) ====")

	var totalKeyGen, totalSign, totalVerify time.Duration
	minKeyGen := time.Duration(1 << 63 - 1)
	minSign := time.Duration(1 << 63 - 1)
	minVerify := time.Duration(1 << 63 - 1)
	maxKeyGen := time.Duration(0)
	maxSign := time.Duration(0)
	maxVerify := time.Duration(0)

	message := []byte("Testing ECDSA signatures")

	for i := 0; i < numRuns; i++ {
		// Key Generation
		start := time.Now()
		privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			log.Fatalf("ECDSA key gen error: %v", err)
		}
		keyGenTime := time.Since(start)

		totalKeyGen += keyGenTime
		if keyGenTime < minKeyGen {
			minKeyGen = keyGenTime
		}
		if keyGenTime > maxKeyGen {
			maxKeyGen = keyGenTime
		}

		// Signing
		hash := sha256.Sum256(message)
		start = time.Now()
		r, s, err := ecdsa.Sign(rand.Reader, privKey, hash[:])
		if err != nil {
			log.Fatalf("ECDSA signing error: %v", err)
		}
		signTime := time.Since(start)
		totalSign += signTime
		if signTime < minSign {
			minSign = signTime
		}
		if signTime > maxSign {
			maxSign = signTime
		}

		// Verification
		start = time.Now()
		valid := ecdsa.Verify(&privKey.PublicKey, hash[:], r, s)
		verifyTime := time.Since(start)
		totalVerify += verifyTime
		if verifyTime < minVerify {
			minVerify = verifyTime
		}
		if verifyTime > maxVerify {
			maxVerify = verifyTime
		}

		if !valid {
			fmt.Printf("Run #%d: ECDSA verification failed!\n", i+1)
		}
	}

	avgKeyGen := totalKeyGen / time.Duration(numRuns)
	avgSign := totalSign / time.Duration(numRuns)
	avgVerify := totalVerify / time.Duration(numRuns)

	fmt.Printf("After %d runs (ECDSA-P256):\n", numRuns)
	fmt.Printf("Key Generation: avg=%v, min=%v, max=%v\n", avgKeyGen, minKeyGen, maxKeyGen)
	fmt.Printf("Signing:        avg=%v, min=%v, max=%v\n", avgSign, minSign, maxSign)
	fmt.Printf("Verification:   avg=%v, min=%v, max=%v\n", avgVerify, minVerify, maxVerify)
	fmt.Println("-----------------------------------")
}

func main() {
	// Number of runs for repeated benchmarks
	numRuns := 200

	// ========== PQC KEM Schemes ==========
	kyber512 := kyber512.Scheme()
	kyber768 := kyber768.Scheme()
	kyber1024 := kyber1024.Scheme()
	frodoScheme := frodo640shake.Scheme()

	RepeatedBenchmarkKEM("Kyber512", kyber512, numRuns)
	RepeatedBenchmarkKEM("Kyber768", kyber768, numRuns)
	RepeatedBenchmarkKEM("Kyber1024", kyber1024, numRuns)
	RepeatedBenchmarkKEM("FrodoKEM", frodoScheme, numRuns)

	// ========== PQC Signature Schemes ==========
	mode44 := mldsa44.Scheme()
	mode65 := mldsa65.Scheme()
	mode87 := mldsa87.Scheme()

	RepeatedBenchmarkSignature("ML-DSA Mode 44", mode44, numRuns)
	RepeatedBenchmarkSignature("ML-DSA Mode 65", mode65, numRuns)
	RepeatedBenchmarkSignature("ML-DSA Mode 87", mode87, numRuns)

	// ========== Traditional Algorithms (Comparison) ==========
	BenchmarkRSA(numRuns)
	BenchmarkECDSA(numRuns)

	// Note: Integration with TLS can be added in future work.
	// This might involve using a PQC KEM to negotiate keys in a TLS handshake,
	// or testing how these algorithms perform in real network scenarios.
}

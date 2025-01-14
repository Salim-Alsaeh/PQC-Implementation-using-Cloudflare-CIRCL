# PQC Implementation using Cloudflare CIRCL

This repository contains a Go-based benchmarking suite for Post-Quantum Cryptographic (PQC) algorithms, leveraging the **Cloudflare CIRCL** library. The implementation provides performance metrics for various lattice-based, code-based, and traditional cryptographic schemes.

## Features
- Benchmarks **Key Encapsulation Mechanisms (KEMs)**:
  - Kyber512
  - Kyber768
  - Kyber1024
  - FrodoKEM
- Benchmarks **Digital Signature Algorithms**:
  - ML-DSA (Modes 44, 65, 87)
- Includes performance comparisons with traditional cryptography:
  - RSA-2048
  - ECDSA (P-256)

## Results
The implementation records:
- Average, minimum, and maximum times for:
  - Key generation
  - Encapsulation/decapsulation
  - Signing/verification
- Comparisons between PQC and traditional cryptographic algorithms.

## Requirements
- **Go**: Version 1.XX or higher
- **Operating System**: macOS (M1), Linux, or Windows
- **CIRCL Library**: [Cloudflare CIRCL](https://github.com/cloudflare/circl)

## Setup
Follow these steps to set up and run the project locally:


0. **Make sure that Go 1.xx or higher is installed on your device**:
1. **Clone the repository**:
    ```bash
    git clone https://github.com/Salim-Alsaeh/PQC-Implementation-using-Cloudflare-CIRCL.git
    cd PQC-Implementation-using-Cloudflare-CIRCL
    ```

2. **Install dependencies**:
    ```bash
    go mod tidy
    ```

3. **Run the program**:
    ```bash
    go run main.go
    ```

## Usage
1. The implementation benchmarks the following algorithms:
    - **Lattice-based KEMs**: Kyber512, Kyber768, Kyber1024, FrodoKEM
    - **Digital Signature Algorithms**: ML-DSA (Modes 44, 65, 87)
    - **Traditional Cryptography**: RSA-2048, ECDSA (P-256)
2. View detailed performance metrics in the terminal upon execution.
3. Modify the `main.go` file to customize the number of test runs or add/remove algorithms.

## Future Work
- **TLS Integration:** Investigating hybrid cryptosystems that combine classical and post-quantum schemes.
- **IoT Compatibility:** Optimizing PQC algorithms for resource-constrained environments like IoT devices.
- **Expanded Benchmarks:** Including additional PQC schemes from emerging standards.

## Contributing
Contributions are welcome! Feel free to open issues or submit pull requests to improve the implementation.

## License
This project is licensed under the MIT License.

## Contact
For questions or suggestions, please contact:
- **Salim Alsaeh**: salim.alsaeh@uob.edu.ly
- **Anas Aljahani**: anas.jahani@uob.edu.ly

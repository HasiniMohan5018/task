# task
This repositary contains a C++ implementation of a proof-of-work hashing system developed as part of a technical assignment. The project focuses on generating valid haash suffixes based on configurable difficulty levels and explores performance constraints when executed on a single-machine CPU environment.

## How to Run

### compile  
```bash
g++ -std=c==17 -O3 solve.cpp -o solve -lpthread -lcrypto

./solve

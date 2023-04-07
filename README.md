# TPM Base Services Analysis

[![Go Reference](https://pkg.go.dev/badge/github.com/rikuks/go-tbs/tbs.svg)](https://pkg.go.dev/github.com/rikuks/go-tbs/tbs)
[![Go Report Card](https://goreportcard.com/badge/github.com/rikuks/go-tbs)](https://goreportcard.com/report/github.com/rikuks/go-tbs)

# Abstract
This library is implemented in Go based on the results of reverse engineering the tbs.dll(TPM Base Services).

# Unanalyzed API
- [ ] Tbsi_Create_Attestation_From_Log
- [ ] Tbsi_FilterLog
- [ ] Tbsi_ShaHash

# Note
Currently only Windows 11 and TPM2.0 are supported.  
Some functions can only be performed in user mode.  
Tested on AMD and ARM CPU architectures.    
Go 1.20.0 or later version is required.

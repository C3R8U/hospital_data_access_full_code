# hospital_data_access_full_code
# Hospital Data Access

A multi-authority attribute-based encryption (MA-ABE) and access-control system for encrypted clinical records. The project combines online/offline ciphertext-policy encryption, blinded edge-assisted decryption, signed off-chain ciphertext packages, and metadata management across Hyperledger Fabric channels.

## 1. Dataset and attribute construction

The input is the **Diabetes 130-US Hospitals for Years 1999–2008** dataset from the UCI Machine Learning Repository. The included `diabetic_data.csv` contains **101,766 hospital encounters**, **71,518 patient identifiers**, and **50 source columns**. `IDS_mapping.csv` provides descriptions for coded admission and discharge fields.

Dataset: <https://archive.ics.uci.edu/dataset/296/diabetes+130-us+hospitals+for+years+1999-2008>

The attribute catalog contains **120 distinct tokens**: **108 clinical tokens** obtained from 18 clinical fields and **12 authorization tokens**. For each clinical field, observed categorical values are ordered by frequency, with lexical ordering used to break ties, and the configured number of values is retained.

| Clinical field | Retained attributes |
| --- | ---: |
| `race` | 6 |
| `gender` | 3 |
| `age` | 10 |
| `admission_type_id` | 8 |
| `admission_source_id` | 10 |
| `discharge_disposition_id` | 10 |
| `medical_specialty` | 10 |
| `diag_1` | 16 |
| `A1Cresult` | 4 |
| `max_glu_serum` | 4 |
| `diabetesMed` | 2 |
| `insulin` | 4 |
| `readmitted` | 3 |
| `time_in_hospital_bin` | 4 |
| `num_lab_procedures_bin` | 4 |
| `num_medications_bin` | 4 |
| `payer_code` | 4 |
| `change` | 2 |
| **Total** | **108** |

The three `_bin` fields are derived with cut points `[2, 5, 9]`, `[20, 40, 60]`, and `[5, 10, 20]`, respectively. Each produces the four labels `low`, `lower_mid`, `upper_mid`, and `high`.

The 12 authorization tokens are:

- Roles: `role=clinician`, `role=nurse`, `role=researcher`, `role=administrator`.
- Purposes: `purpose=treatment`, `purpose=research`, `purpose=operations`.
- Channels: `channel=clinical`, `channel=laboratory`, `channel=administrative`.
- Organizations: `organization=org_a`, `organization=org_b`.

Each token is assigned to one of **four attribute authorities**, using its catalog position modulo the number of authorities. Encrypted example payloads are fixed at **2,048 bytes** and exclude the encounter and patient identifiers.

## 2. Model configuration

The canonical parameters are stored in `config/study.json`, and the network topology is stored in `config/fabric_network.json`.

### Attribute policies and offline cache

| Parameter | Value |
| --- | --- |
| Random seed | `20261109` |
| Attribute universe | 120 tokens |
| Attribute authorities | 4 |
| Policy sizes | 20, 40, 60, 80, 100 leaf attributes |
| Policy structure | Conjunction of OR clauses |
| Maximum leaves per OR clause | 20 |
| Attribute labels | Unique within each policy |
| LSSS matrix entries | `-1`, `0`, `1` |
| Maximum LSSS matrix columns | 16 |
| Offline vector dimension | 16 |
| Disposable cache slots | 8 |
| Configured cache low-watermark | 20% |
| Configured cache workers | 16 |

A policy is represented by a linear secret-sharing scheme (LSSS) pair `(M, rho)`, where row `i` has attribute label `rho(i)`. The policy generator builds OR clauses connected by AND operators. Each authorized reconstruction selects one matching leaf from every OR clause and obtains coefficients `gamma_i` satisfying:

```text
sum_i gamma_i * M[i] = (1, 0, ..., 0)
```

### Cryptographic parameters

| Parameter | Value |
| --- | --- |
| Configured security target | 128 bits |
| Group construction | Symmetric composite-order bilinear pairing, PBC Type A1 |
| Composite order | `N = p1 * p2 * p3` |
| Prime-factor sizes | 1,024 bits each |
| Composite-order size | 3,072 bits |
| Pairing embedding degree | 2 |
| Pairing library | PBC 0.5.14 |
| Integer arithmetic library | GMP 6.2.1 |
| Data encryption | AES-128-GCM |
| Nonce length | 96 bits |
| Key derivation | HKDF-SHA256, 128-bit output |
| Ciphertext package digest | SHA-256 |
| Owner signature | Ed25519 |
| Policy digest | SHA-256 of the salt and canonical policy serialization |

For each attribute `x`, an authority samples secret exponents `(alpha_x, y_x)` and publishes the components:

```text
A_x       = e(g, g)^alpha_x
B_x       = g^y_x
SK[u, x]  = g^alpha_x * H(GID_u)^y_x
```

All attributes issued to a user share the same global identity `GID_u`. Authority secrets are managed separately, and the user's key collection retains the corresponding attribute labels.

### Online/offline encryption

A disposable offline slot samples vectors `v = (s, v2, ..., vD)` and `w = (0, w2, ..., wD)` and prepares the following elements for each attribute:

```text
E_j = e(g, g)^v_j        W_j = g^w_j
X_x = A_x^r_x           Y_x = g^r_x           Z_x = B_x^r_x
```

The online stage combines these elements using the selected policy matrix:

```text
lambda_i = M[i] * v
omega_i  = M[i] * w
C1_i     = X_rho(i) * product_j E_j^M[i,j]
C2_i     = Y_rho(i)
C3_i     = Z_rho(i) * product_(j>=2) W_j^M[i,j]
C0       = R * E_1
```

`R` is a random target-group element used to derive the AES-128-GCM content key. Authenticated associated data contains the channel identifier, salted policy digest, and object version. The ciphertext record contains the policy, row components, encapsulated element, authenticated ciphertext, nonce, and confirmation digest; an Ed25519 signature authenticates the serialized record and is carried with its metadata reference.

### Edge-assisted decryption

A user with an authorized attribute set selects an invertible scalar `z` and delegates blinded key elements to an edge processor:

```text
TK[u, x] = SK[u, x]^(1/z)
TK[H]    = H(GID_u)^(1/z)
P        = product_(i in I) (
             e(TK[H], C3_i) / e(TK[u, rho(i)], C2_i)
           )^gamma_i
L        = product_(i in I) C1_i^gamma_i
Z        = L * P^z = e(g, g)^s
R        = C0 / Z
```

The user checks key confirmation and AES-GCM authentication before accepting the recovered plaintext. Ciphertext package verification checks the owner signature, policy digest, channel binding, object version, and package digest.

## 3. Network and workload configuration

| Parameter | Value |
| --- | --- |
| Hyperledger Fabric | 2.4 |
| Organizations | `OrgA`, `OrgB`, `OrgC` |
| Peers | 6 (2 per organization) |
| Orderers | 3 |
| Ordering service | Raft |
| Business channels | `clinical`, `laboratory`, `administrative` |
| Chaincode name | `hospitalmeta` |
| Transaction method | `PutMetadata` |
| Maximum transactions per block | 20 |
| Batch timeout | 100 ms |
| Preferred block size | 524,288 bytes |
| Offered request rates | 500, 1,000, 2,000, 3,000, 4,000 requests/s |
| Load-test repetitions | 10 per rate |
| Load-test duration | 60 seconds per trial |
| Maximum concurrent requests | 512 |

| Channel | Member organizations | Peer assignments | Required endorsing organizations |
| --- | --- | --- | --- |
| `clinical` | OrgA, OrgB | `peer0.orga`, `peer0.orgb` | OrgA and OrgB |
| `laboratory` | OrgA, OrgC | `peer1.orga`, `peer0.orgc` | OrgA and OrgC |
| `administrative` | OrgB, OrgC | `peer1.orgb`, `peer1.orgc` | OrgB and OrgC |

The single-channel workload places all six peers in `clinical` and uses OrgA and OrgB as endorsers. The application records transaction confirmations separately by channel and aggregates committed metadata transactions over the measured execution interval. Encrypted clinical objects remain in off-chain storage; ledger transactions carry metadata references and integrity information.

The clinical capacity model uses **20,000 reports per day**, an **8-hour reporting window**, and a **4-fold peak-load multiplier**.

## 4. Python environment and commands

Run the following commands from the project root. Python dependencies are declared in `requirements.txt`.

```bash
python -m pip install -r requirements.txt
python -m pytest -q tests/
python scripts/run_experiment.py --backend algebra-check
python scripts/statistical_tests.py
python scripts/ablation.py
python scripts/cache_scaling.py --backend algebra-check --workers 1,4,16 --slots 16
python scripts/capacity_analysis.py
python scripts/make_figures.py
python scripts/summarize_results.py
```

The `algebra-check` backend evaluates the group identities using modular exponent arithmetic. The `pbc-a1` backend uses the native pairing interface and the configured public pairing parameters.

### Native pairing tools

Install PBC 0.5.14, GMP, and a C compiler, then run:

```bash
bash scripts/build_native.sh
python scripts/create_pairing_parameters.py --bits 1024
python scripts/run_experiment.py --backend pbc-a1
python scripts/create_native_trace.py
```

The generated public parameter files are `params/public/a1.param` and `params/public/g1.bin`; the compiled library is `build/libhealthshare_pbc.so`.

### Signed object generation and access

A password-protected authority key store preserves attribute secrets and the owner signing key across processes. Set `HOSPITAL_KEYSTORE_PASSPHRASE` in the environment and keep the key-store file outside the project directory.

```bash
python scripts/create_key_store.py --backend pbc-a1 --output /secure/path/authority.enc
python scripts/build_fabric_workload.py --backend pbc-a1 --layout three --count 150 --key-file /secure/path/authority.enc
python scripts/build_fabric_workload.py --backend pbc-a1 --layout single --count 150 --key-file /secure/path/authority.enc
python scripts/check_ciphertext_roundtrip.py --key-file /secure/path/authority.enc --limit 10
python scripts/validate_ciphertext_metadata.py
```

For the three-channel workload, ciphertext packages are stored in `data/derived/fabric_ciphertexts/`, and transaction templates are written to `data/derived/fabric_transactions.jsonl`. The single-channel equivalents use the `_single` suffix.

### IPFS and Fabric Gateway

The IPFS uploader accepts an API endpoint and updates transaction templates with content addresses:

```bash
python scripts/ipfs_upload.py --endpoint http://127.0.0.1:5001
```

Install the Gateway client dependencies:

```bash
cd scripts
npm install
cd ..
```

Deploy the `hospitalmeta` chaincode on the configured channels. Connection settings are read from `FABRIC_GATEWAYS_JSON`, which identifies the channel-specific peer endpoint, TLS certificate, client certificate, client key, and membership service provider ID. The variables `FABRIC_LAYOUT`, `FABRIC_CHAINCODE`, `FABRIC_LOADS`, `FABRIC_DURATION_MS`, `FABRIC_REPETITIONS`, and `FABRIC_IN_FLIGHT` control the load client.

```bash
FABRIC_LAYOUT=single node scripts/fabric_load.js
FABRIC_LAYOUT=three node scripts/fabric_load.js
python scripts/analyze_fabric.py
```

Use `python scripts/analyze_fabric.py --block-records PATH` to include channel block-event records containing `channel`, `number`, `timestamp_ms`, and `transaction_count`.

## 5. Measurements and output organization

The configured workload uses **20 warm-up runs** and **100 timed runs** at each policy size. Timing summaries report sample means, standard deviations, and **95% confidence intervals**. Paired comparisons use two-sided paired Student's *t*-tests with Holm adjustment.

The measurement fields distinguish cached online encryption, direct encryption, package preverification, edge transformation, user recovery, direct decryption, ciphertext size, and local access time. The load client reports issued, committed, and failed transactions by channel, together with confirmation latency statistics.

## 6. File guide

Each entry describes one source, configuration, test, or output file. Hashed ciphertext filenames share the same format and are grouped by directory.

### Project files and configuration

| File | Purpose |
| --- | --- |
| `README.md` | Describes the system, parameters, commands, and project files. |
| `MODEL_SPEC.md` | Documents key structures, policy matrices, ciphertext elements, decryption identities, and metric definitions. |
| `EXPERIMENT_NOTES.md` | Records workload inputs, execution commands, and measurement conventions. |
| `requirements.txt` | Declares Python packages used by the project. |
| `config/study.json` | Holds the random seed, model parameters, policy sizes, cache settings, and trial schedule. |
| `config/fabric_network.json` | Defines organizations, peer membership, endorsers, ordering parameters, and channel layouts. |

### Python package

| File | Purpose |
| --- | --- |
| `healthshare/__init__.py` | Initializes the `healthshare` package. |
| `healthshare/abe.py` | Implements authority keys, disposable encryption slots, ciphertext packaging, verification, and recovery. |
| `healthshare/analysis.py` | Aggregates Fabric transaction and block statistics for comparison. |
| `healthshare/cache_parallel.py` | Coordinates independent offline-slot generation workers. |
| `healthshare/data.py` | Loads hospital records, derives clinical attributes, and prepares encrypted payloads. |
| `healthshare/experiments.py` | Executes timed cryptographic operations and records trial measurements. |
| `healthshare/fabric_config.py` | Loads and validates network configuration and batching information. |
| `healthshare/groups.py` | Provides modular group operations and the PBC native pairing interface. |
| `healthshare/key_store.py` | Encrypts and loads persistent authority and signing keys. |
| `healthshare/policy.py` | Constructs monotone policies, LSSS matrices, and reconstruction coefficients. |
| `healthshare/storage.py` | Converts between local ciphertext paths and storage references. |
| `healthshare/vectors.py` | Constructs deterministic group arithmetic and decryption vectors. |

### Native and blockchain components

| File | Purpose |
| --- | --- |
| `native/pbc_bridge.c` | Exposes native pairing and group operations through a C interface. |
| `native/setup_a1.c` | Generates public Type A1 pairing parameters and a subgroup generator. |
| `chaincode/metadata/main.go` | Implements the Fabric chaincode for storing signed ciphertext metadata references. |
| `chaincode/metadata/go.mod` | Declares the Go module and chaincode dependencies. |
| `scripts/fabric_load.js` | Submits metadata transactions through Fabric Gateway and records commit outcomes. |
| `scripts/package.json` | Declares JavaScript dependencies for the Gateway load client. |

### Command-line scripts

| File | Purpose |
| --- | --- |
| `scripts/ablation.py` | Measures component-level encryption and access configurations and checks invalid requests. |
| `scripts/analyze_fabric.py` | Summarizes committed transactions and optional per-channel block records. |
| `scripts/build_fabric_workload.py` | Generates signed encrypted objects and channel-specific metadata transaction templates. |
| `scripts/build_native.sh` | Compiles the native PBC bridge and parameter generator. |
| `scripts/cache_scaling.py` | Measures offline-slot creation under different worker counts. |
| `scripts/capacity_analysis.py` | Calculates reporting-load and cache-capacity estimates from configured inputs. |
| `scripts/check_ciphertext_roundtrip.py` | Checks stored ciphertext integrity and decrypts objects with a persistent key store. |
| `scripts/check_fabric_network.py` | Displays the configured Fabric channel and batch-ordering layout. |
| `scripts/create_decryption_vector.py` | Writes a deterministic decryption known-answer vector. |
| `scripts/create_key_store.py` | Creates a password-protected authority key store. |
| `scripts/create_native_trace.py` | Saves serialized native-pairing encryption and decryption intermediates. |
| `scripts/create_pairing_parameters.py` | Produces public composite-order pairing parameters and a subgroup generator. |
| `scripts/ipfs_upload.py` | Uploads encrypted objects to IPFS and updates their metadata references. |
| `scripts/make_figures.py` | Draws encryption, access, integrity, size, and batch-verification plots. |
| `scripts/run_experiment.py` | Runs the configured clinical-policy timing workload. |
| `scripts/statistical_tests.py` | Performs paired timing tests and Holm correction. |
| `scripts/summarize_results.py` | Summarizes dataset and operation measurements. |
| `scripts/validate_ciphertext_metadata.py` | Checks the signatures and integrity fields of stored ciphertext metadata. |
| `scripts/write_manifest.py` | Records input checksums and runtime package versions. |

### Dataset and derived records

| File or directory | Purpose |
| --- | --- |
| `data/raw/diabetic_data.csv` | Contains the original hospital encounter records. |
| `data/raw/IDS_mapping.csv` | Describes coded admission and discharge values. |
| `data/derived/attribute_catalog.csv` | Lists clinical and administrative attribute tokens with their sources. |
| `data/derived/code_descriptions.json` | Contains parsed descriptions of coded hospital fields. |
| `data/derived/readmission_by_age.csv` | Counts readmission categories by age group. |
| `data/derived/policy_instances.jsonl` | Stores generated attribute sets and access-policy matrices. |
| `data/derived/fabric_transactions.jsonl` | Stores three-channel signed metadata transaction templates. |
| `data/derived/fabric_transactions_single.jsonl` | Stores single-channel signed metadata transaction templates. |
| `data/derived/fabric_ciphertexts/*.bin` | Contains serialized encrypted packages for the three-channel workload. |
| `data/derived/fabric_ciphertexts_single/*.bin` | Contains serialized encrypted packages for the single-channel workload. |

### Tests

| File | Purpose |
| --- | --- |
| `tests/test_analysis.py` | Checks transaction aggregation and channel comparison logic. |
| `tests/test_engine.py` | Exercises access policies, valid decryption, metadata verification, and tamper rejection. |
| `tests/test_keystore.py` | Checks encrypted key-store persistence and stored-object access. |
| `tests/test_native_pairing.py` | Tests group operations using the native PBC interface. |
| `tests/test_parallel_cache.py` | Checks parallel offline-slot generation. |
| `tests/test_vectors.py` | Checks deterministic decryption intermediates and signed metadata validation. |
| `tests/vectors/decryption.json` | Contains fixed group parameters, intermediate values, and expected decryption output. |

### Analysis files

| File or directory | Purpose |
| --- | --- |
| `results/performance_raw.csv` | Stores individual operation timings and ciphertext sizes. |
| `results/performance_summary.csv` | Stores per-metric means, standard deviations, and confidence intervals. |
| `results/paired_tests.csv` | Stores paired comparison statistics and adjusted probability values. |
| `results/ablation.csv` | Stores component-level encryption and access timing summaries. |
| `results/cache_parallel.csv` | Stores offline-cache worker measurements. |
| `results/capacity_analysis.json` | Stores reporting-load, cache-capacity, and ledger-size calculations. |
| `results/dataset_profile.json` | Stores dataset counts, readmission categories, and missing-field summaries. |
| `results/fabric_analysis.json` | Stores aggregated Fabric transaction and block analysis. |
| `results/hardware.json` | Records host processor and runtime environment information. |
| `results/integrity_checks.json` | Stores ciphertext transform, integrity, and channel-isolation checks. |
| `results/invalid_request_checks.json` | Stores invalid-request rejection and edge-invocation counts. |
| `results/local_metadata.sqlite` | Stores local metadata for the encrypted-storage pipeline. |
| `results/manifest.json` | Stores input file hashes and installed package information. |
| `results/metadata_single_checks.json` | Stores signature and integrity checks for single-channel metadata. |
| `results/metadata_three_checks.json` | Stores signature and integrity checks for three-channel metadata. |
| `results/metrics.json` | Stores workload-level settings and measured operation metrics. |
| `results/roundtrip_single.json` | Stores single-channel stored-ciphertext decryption checks. |
| `results/roundtrip_three.json` | Stores three-channel stored-ciphertext decryption checks. |
| `results/run.log` | Records timing-workload execution messages. |
| `results/study_summary.json` | Collects dataset, timing, and configuration summaries. |
| `results/training.log` | Records dataset preparation and attribute-generation messages. |
| `results/verification_batches.csv` | Stores batch verification timing summaries. |
| `results/encrypted_objects/*.bin` | Contains encrypted objects from the local storage workload. |
| `results/figures/access.png` | Plots edge transformation, user recovery, and direct decryption. |
| `results/figures/ciphertext_size.png` | Plots serialized ciphertext size by policy scale. |
| `results/figures/encryption.png` | Plots cached online and direct encryption. |
| `results/figures/integrity.png` | Plots ciphertext package verification time. |
| `results/figures/online_encryption.png` | Plots online and direct encryption timings. |
| `results/figures/user_recovery.png` | Plots user-side recovery time. |
| `results/figures/verification_batches.png` | Plots batch verification time. |

## 7. Dataset citation

Strack, B., DeShazo, J. P., Gennings, C., Olmo, J. L., Ventura, S., Cios, K. J., and Clore, J. N. (2014). *Impact of HbA1c Measurement on Hospital Readmission Rates: Analysis of 70,000 Clinical Database Patient Records*. **BioMed Research International**, 2014, 781670. <https://doi.org/10.1155/2014/781670>

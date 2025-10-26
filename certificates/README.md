# Certificates Package

The `certificates` package implements the core components of a Decentralized Public Key Infrastructure (DPKI) designed for distributed P2P networks. The primary goals of this system are:

1.  **Preventing Identity Preemption Attacks**: Uses cryptographic IDs to fundamentally block identity spoofing.
2.  **Ensuring Data Integrity**: Manages key-change history transparently through individual log chains to prevent tampering.
3.  **Scalability and Performance**: Designed for efficiency in large-scale networks through data sharding and an optimized DB schema.

This package constitutes the identity and data management layer of the overall architecture, built upon Post-Quantum Cryptography (PQC) algorithms: **ML-KEM 1024** for key exchange and **ML-DSA-87** for digital signatures.

---

## 1. Identity Definition: Public Key Hash-based ID

The most critical design principle is defining a node's (Satellite's) ID as an unpredictable cryptographic value to defend against **Identity Preemption Attacks**.

-   **ID Definition**: `Node_ID = HASH(Public_Key)`
    -   In the actual implementation, the ID is the `blake3` hash of the serialized `Public` struct (see the `(Public).ID()` method).
-   **Security Implication**: Since the ID is derived directly from the node's public key, an attacker cannot predict the private key a node will generate in the future. Therefore, it is **mathematically infeasible** to pre-calculate and register another node's ID on a DHT (Distributed Hash Table), thus preventing preemption attacks.

---

## 2. Data Integrity: Individual Log Chains

Instead of a global ledger, this package provides the functionality to create and manage independent **individual log chains** for each node.

-   **Structure**: The `StoredPublicKey` struct contains a `previousHash` field that points to the previous version of the key block. This forms a hash-linked chain of a node's key-change history.
-   **Data Integrity**: Each block in the chain (representing a key update) is signed with the node's `ML-DSA` private key. This ensures that even the quorum nodes responsible for replicating the data cannot forge or roll back the history.
-   **Web of Trust**: The `StoredPublicKey` can also store `signatures` from other nodes, providing a foundation for a Web of Trust where participants can vouch for the authenticity of each other's keys without a central authority.

---

## 3. Performance Optimization: DB Schema

To enable quorum nodes to efficiently handle "latest key lookups" and "full history audits," data is stored in `pebble.DB` using the following separated key schema:

1.  **Latest Block Reference Key**
    -   **Key**: `certificates:stored_public_key:<Node_ID>:latest`
    -   **Value**: `<Latest_Block_ID>`
    -   **Purpose**: Used to quickly look up the latest public key block ID for a specific node in O(1) time. Most "key lookup" requests are handled using this key.

2.  **Individual Block Data Key**
    -   **Key**: `certificates:stored_public_key:<Node_ID>:<Block_ID>`
    -   **Value**: `<Serialized_StoredPublicKey_Data>`
    -   **Purpose**: Used to retrieve the data of a specific `StoredPublicKey` block version, using either the `Block_ID` obtained from the "Latest Block Reference Key" or a previous hash. This is necessary for auditing the full history or performing cross-validation.

With this schema separation, 99% of typical key lookup requests can be processed extremely quickly with just two `Get` operations, without needing to scan the entire log.

---

## 4. Core Components and Functionality

-   **`cert.go`**:
    -   `Private` / `Public` structs: Manage ML-KEM and ML-DSA key pairs.
    -   `ID()`: Generates a unique ID from a public key.
    -   `SignData` / `VerifyDataSignature`: Provides functions for signing and verifying data.
-   **`store.go` & `store_key.go`**:
    -   `Store`: Persistently stores and manages public key chains using `pebble.DB`.
    -   `StoredPublicKey`: The fundamental block unit of the log chain.
    -   `StorePublicKey`, `UpdateLatestPublicKeyReference`: Handle the core logic for storing new key blocks and updating the latest reference.
    -   `GetLatestPublicKeyReference`, `GetStoredPublicKey`: Retrieve key information using the optimized DB schema.
    -   `LockPublicKey` / `RLockPublicKey`: Provides key-level locking to resolve concurrency issues.


## 2. 주요 구성 요소

### `cert.go` - 암호화 키 쌍 관리

-   **알고리즘**: 키 교환을 위해 **ML-KEM 1024**, 디지털 서명을 위해 **ML-DSA-87** 양자내성암호 알고리즘을 사용합니다.
-   `Private` / `Public`: 키 쌍을 관리하는 구조체입니다. `Public` 키는 네트워크에 공유되며, 바이너리 형태로 직렬화/역직렬화가 가능합니다.
-   `NewPrivate`: 새로운 `Private` 키와 `Public` 키 쌍을 생성합니다.

### `store.go` & `store_key.go` - 공개키 저장 및 관리

-   `Store`: `pebble.DB`를 백엔드로 사용하여 공개키와 관련 메타데이터를 영속적으로 저장하고 관리합니다.
-   `StoredPublicKey`: 데이터베이스에 저장되는 기본 단위(블록)입니다. 다음 정보를 포함합니다.
    -   `id`: 키 소유자의 고유 ID (`HASH(PublicKey)`).
    -   `publicKey`: `Public` 키.
    -   `previousHash`: 이전 버전의 `StoredPublicKey` 블록 해시.
    -   `signatures`: 이 키를 신뢰하는 다른 노드들의 서명 맵.
    -   `createdAt`: 생성 타임스탬프.
-   **주요 기능**:
    -   `StorePublicKey`: 새로운 버전의 공개키를 저장합니다.
    -   `GetLatestStoredPublicKey`: 특정 ID에 대한 최신 공개키를 조회합니다.
    -   `AddSignatureToLatest`: 최신 공개키에 다른 참여자의 서명을 추가하고, 이를 새로운 버전의 키 블록으로 기록합니다.
    -   `LockPublicKey` / `RLockPublicKey`: 키별 잠금 기능을 제공하여 동시성 문제를 방지합니다.

## 3. 전체 통신 및 검증 흐름

1.  **신뢰점 생성 (외부 공유)**: `노드 A`는 자신의 ID(`ID_A = HASH(A_PK)`)를 웹사이트, QR 코드 등 신뢰할 수 있는 외부 채널을 통해 `노드 B`에게 전달합니다.
2.  **쿼럼 등록 (DHT STORE)**: `A`는 자신의 공개키 정보(`StoredPublicKey`)를 보관할 노드 그룹(쿼럼)의 주소를 `ID_A`를 키로 하여 DHT에 등록합니다.
3.  **쿼럼 발견 (DHT FIND)**: `B`는 `A`와 통신하기 위해 `ID_A`를 이용해 DHT에서 `A`의 쿼럼 주소를 조회합니다.
4.  **교차 검증**: `B`는 `A`의 쿼럼 노드들로부터 `A`의 전체 `StoredPublicKey`를 가져옵니다.
5.  **수학적 신원 확인**:
    -   `B`는 전달받은 `A`의 공개키를 직접 해시합니다.
    -   `HASH(A_PK)`가 1단계에서 얻은 `ID_A`와 일치하는지 대조합니다.
    -   일치하면, `B`는 이 공개키가 진짜 `A`의 것임을 수학적으로 확신하고, 함께 받은 KEM 공개키를 사용해 안전한 통신을 시작합니다.

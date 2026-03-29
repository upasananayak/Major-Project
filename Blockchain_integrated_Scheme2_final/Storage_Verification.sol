// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract StorageVerification {
    struct ZKParams {
        uint256 p; uint256 q; uint256 g; uint256 h;
    }

    struct FileRecord {
        bytes32 iotRoot;
        bytes32 commitmentHash;
        ZKParams params;
        uint256[] commitments;
        bool registered;
        bool verified;
        bool isDeleted;
    }

    mapping(string => FileRecord) private files;
    
    // NEW: History tracking
    mapping(string => string[]) public fileHistory;
    event FileDeleted(string indexed humanName);
    event FileRegistered(string indexed humanName, string uniqueId, uint256 versionIndex);

    function registerFile(
        string memory humanName,     
        string memory uniqueId,    
        bytes32 rootHash,
        bytes32 commitmentHash,
        uint256[] memory commitments,
        uint256[4] memory zkvals 
    ) public {
        require(!files[uniqueId].registered, "Unique ID already exists");
        
        FileRecord storage f = files[uniqueId];
        f.iotRoot = rootHash;
        f.commitmentHash = commitmentHash;
        f.commitments = commitments;
        f.params = ZKParams(zkvals[0], zkvals[1], zkvals[2], zkvals[3]);
        f.registered = true;

        // Push to history
        fileHistory[humanName].push(uniqueId);
        emit FileRegistered(humanName, uniqueId, fileHistory[humanName].length);
    }

    // Storage_Verification.sol

    function verifyTrustless(
        string memory uniqueId,
        bytes32[] memory leafTags,
        bytes32[][] memory proofs,
        uint256[][] memory leafCounts,
        uint8[][] memory sigmas,
        uint256 mSum,
        uint256 rSum,
        uint256[] memory indices,
        uint256[] memory coefficients,
        uint256 z,                 // nonce
        bytes32 proof_value        // hash binding
    ) public {
    FileRecord storage f = files[uniqueId];
    require(f.registered, "File not registered");

    // 1. Verify EVERY challenged chunk in the Merkle Tree
    for (uint256 i = 0; i < leafTags.length; i++) {
        bytes32 currentHash = leafTags[i];
        for (uint256 j = 0; j < proofs[i].length; j++) {
            uint256 nodeLeafCount = leafCounts[i][j] * 2;
            if (sigmas[i][j] == 0) {
                currentHash = keccak256(abi.encodePacked(nodeLeafCount, proofs[i][j], currentHash));
            } else {
                currentHash = keccak256(abi.encodePacked(nodeLeafCount, currentHash, proofs[i][j]));
            }
        }
        require(currentHash == f.iotRoot, "Merkle verification failed for a chunk");
    }

    // 2. PEDERSEN LOGIC (Already correct, stays the same)
    uint256 term1 = pow(f.params.g, mSum, f.params.p);
    uint256 term2 = pow(f.params.h, rSum, f.params.p);
    uint256 pedRecomputed = mulmod(term1, term2, f.params.p);

    uint256 expectedAgg = 1;
    for (uint256 i = 0; i < indices.length; i++) {
        uint256 Ci = f.commitments[indices[i]];
        uint256 ai = coefficients[i] % f.params.q;
        expectedAgg = mulmod(expectedAgg, pow(Ci, ai, f.params.p), f.params.p);
    }
    bytes32 recomputed = keccak256(
        abi.encode(expectedAgg, z) 
    );
    require(recomputed == proof_value, "Challenge-binding hash mismatch");


    f.verified = (pedRecomputed == expectedAgg && recomputed == proof_value);

}
    
    // Helper to see history length
    function getHistoryLength(string memory humanName) public view returns (uint256) {
        return fileHistory[humanName].length;
    }
    
    function getStatus(string memory uniqueId) public view returns (bool) {
        return files[uniqueId].verified;
    }

    // Math helpers (Same as your original)
    function pow(uint256 base, uint256 exponent, uint256 modulus) internal pure returns (uint256) {
        uint256 result = 1;
        base = base % modulus;
        while (exponent > 0) {
            if (exponent % 2 == 1) result = mulmod(result, base, modulus);
            base = mulmod(base, base, modulus);
            exponent /= 2;
        }
        return result;
    }
    // 1. GET HISTORY: Returns the list of all version IDs for a file
    function getHistory(string memory humanName) public view returns (string[] memory) {
        return fileHistory[humanName];
    }

    // 2. DELETE FILE: Marks the LATEST version as deleted
    function deleteFile(string memory humanName) public {
        string[] memory history = fileHistory[humanName];
        require(history.length > 0, "File not found");
        
        // Mark the latest version as deleted
        string memory latestId = history[history.length - 1];
        files[latestId].isDeleted = true;
        
        emit FileDeleted(humanName);
    }
    // 3. CHECK STATUS: Returns true if the file is marked deleted
    function isFileDeleted(string memory uniqueId) public view returns (bool) {
        return files[uniqueId].isDeleted;
    }
}


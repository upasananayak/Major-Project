// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract StorageVerification {

    // -----------------------------
    // Structures
    // -----------------------------

    struct FileVersion {
        bytes32 rootHash;         // IMHT root
        bytes32 commitmentHash;   // Pedersen commitment hash
        bool verified;            // verification result
        uint256 timestamp;        // block timestamp
    }

    struct FileMeta {
        bool exists;              // file registered or not
        uint256 latestVersion;    // version counter
        mapping(uint256 => FileVersion) versions;
    }

    // fileId => metadata
    mapping(string => FileMeta) private files;

    // -----------------------------
    // Events
    // -----------------------------

    event FileRegistered(
        string fileId,
        bytes32 rootHash,
        bytes32 commitmentHash
    );

    event FileUpdated(
        string fileId,
        uint256 version,
        bytes32 rootHash,
        bytes32 commitmentHash
    );

    event VerificationResult(
        string fileId,
        uint256 version,
        bool success
    );

    // -----------------------------
    // File Registration (Version 1)
    // -----------------------------

    function registerFile(
        string memory fileId,
        bytes32 rootHash,
        bytes32 commitmentHash
    ) public {
        require(!files[fileId].exists, "File already registered");

        FileMeta storage f = files[fileId];
        f.exists = true;
        f.latestVersion = 1;

        f.versions[1] = FileVersion({
            rootHash: rootHash,
            commitmentHash: commitmentHash,
            verified: false,
            timestamp: block.timestamp
        });

        emit FileRegistered(fileId, rootHash, commitmentHash);
    }

    // ------------------------------------------------
    // Update File (insert / modify / delete)
    // Creates a NEW VERSION (immutability preserved)
    // ------------------------------------------------

    function updateFile(
        string memory fileId,
        bytes32 rootHash,
        bytes32 commitmentHash
    ) public {
        require(files[fileId].exists, "File not registered");

        FileMeta storage f = files[fileId];
        f.latestVersion += 1;

        f.versions[f.latestVersion] = FileVersion({
            rootHash: rootHash,
            commitmentHash: commitmentHash,
            verified: false,
            timestamp: block.timestamp
        });

        emit FileUpdated(
            fileId,
            f.latestVersion,
            rootHash,
            commitmentHash
        );
    }

    // ------------------------------------------------
    // Verifier submits verification result
    // ------------------------------------------------

    function submitVerification(
        string memory fileId,
        uint256 version,
        bytes32 computedRoot,
        bytes32 computedCommitment
    ) public {
        require(files[fileId].exists, "File not registered");
        require(version > 0 && version <= files[fileId].latestVersion,
                "Invalid version");

        FileVersion storage v = files[fileId].versions[version];

        bool success =
            (v.rootHash == computedRoot) &&
            (v.commitmentHash == computedCommitment);

        v.verified = success;

        emit VerificationResult(fileId, version, success);
    }

    // -----------------------------
    // View / Getter Functions
    // -----------------------------

    function getLatestVersion(string memory fileId)
        public
        view
        returns (uint256)
    {
        require(files[fileId].exists, "File not registered");
        return files[fileId].latestVersion;
    }

    function getLatestStatus(string memory fileId)
        public
        view
        returns (bool)
    {
        require(files[fileId].exists, "File not registered");
        uint256 v = files[fileId].latestVersion;
        return files[fileId].versions[v].verified;
    }

    function getVersionRoot(
        string memory fileId,
        uint256 version
    )
        public
        view
        returns (bytes32)
    {
        require(files[fileId].exists, "File not registered");
        require(version > 0 && version <= files[fileId].latestVersion,
                "Invalid version");
        return files[fileId].versions[version].rootHash;
    }

    function getVersionCommitment(
        string memory fileId,
        uint256 version
    )
        public
        view
        returns (bytes32)
    {
        require(files[fileId].exists, "File not registered");
        require(version > 0 && version <= files[fileId].latestVersion,
                "Invalid version");
        return files[fileId].versions[version].commitmentHash;
    }

    function fileExists(string memory fileId)
     public
     view
     returns (bool)
   {
    return files[fileId].exists;
   }

   function getLatestRootWithVersion(string memory fileId)
    public
    view
    returns ( bytes32 rootHash)
   {
    FileMeta storage f = files[fileId];
    require(f.latestVersion > 0, "File not registered");

    rootHash = f.versions[f.latestVersion].rootHash;
    }

}

// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/**
 * @title Xarv
 * @notice Minimal ERC-20 with permit, guarded mint/burn, and optional signature-gated minting.
 * @dev Built for mainnet deployment: explicit admin, bounded mint, replay-safe permits, and no ETH handling.
 */
contract Xarv {
    // =============================================================
    //                            METADATA
    // =============================================================

    string public constant name = "Xarv";
    string public constant symbol = "XARV";
    uint8 public constant decimals = 18;

    // =============================================================
    //                           CONFIG / ROLES
    // =============================================================

    // Generic immutables (randomized, constructor-set).
    // They have no privileged fund-sink behavior; used only as optional signer hints / observers.
    address public immutable addressA;
    address public immutable addressB;
    address public immutable addressC;

    // Authority role is "director" (two-step handoff).
    address public director;
    address public pendingDirector;

    // Pause flag.
    bool public lanePaused;

    // Mint controls.
    uint256 public immutable maxSupply;
    uint256 public mintedTotal;

    // Optional signature-gated minting.
    bool public mintGateOn;
    mapping(address => bool) public mintGateSigner;
    mapping(bytes32 => bool) public usedMintAuth;

    // =============================================================
    //                             ERC-20
    // =============================================================

    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    // =============================================================
    //                             PERMIT
    // =============================================================

    // keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)")
    bytes32 private constant _EIP712_DOMAIN_TYPEHASH =
        0x36c25de3bdc9f4a856c11d1c44b9c3a3f1f8f0d53e5b72c6d3b66a6a10b0b54c;

    // keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)")
    bytes32 private constant _PERMIT_TYPEHASH =
        0x6e71edae12b1b97f4d1f60370fef10105fa2faae0126114a169c64845d6126c9;

    bytes32 private immutable _domainSalt;
    bytes32 private immutable _nameHash;
    bytes32 private immutable _versionHash;
    mapping(address => uint256) public nonces;

    // =============================================================
    //                             REENTRANCY
    // =============================================================

    uint256 private _lock;

    // =============================================================
    //                              EVENTS
    // =============================================================

    event XR_Transfer(address indexed from, address indexed to, uint256 amount);
    event XR_Approval(address indexed owner, address indexed spender, uint256 amount);

    event XR_DirectorProposed(address indexed currentDirector, address indexed proposedDirector);
    event XR_DirectorAccepted(address indexed previousDirector, address indexed newDirector);
    event XR_LanePauseSet(bool paused);

    event XR_Mint(address indexed to, uint256 amount, bytes32 ref);
    event XR_Burn(address indexed from, uint256 amount);
    event XR_MintGateSet(bool enabled);
    event XR_MintSignerSet(address indexed signer, bool allowed);
    event XR_MintAuthUsed(bytes32 indexed authHash, address indexed to, uint256 amount);

    // =============================================================
    //                              ERRORS
    // =============================================================

    error XR_Unauthorized();
    error XR_ZeroAddress();
    error XR_LanePaused();

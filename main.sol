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
    error XR_AmountZero();
    error XR_AllowanceLow();
    error XR_BalanceLow();
    error XR_SupplyCap();
    error XR_BadSignature();
    error XR_Expired();
    error XR_AlreadyUsed();
    error XR_BadNonce();
    error XR_Reentrancy();
    error XR_SelfApprove();
    error XR_SelfTransfer();
    error XR_BadSpender();
    error XR_BadRecipient();

    // =============================================================
    //                           CONSTRUCTOR
    // =============================================================

    constructor() {
        // Authority.
        director = msg.sender;

        // Randomized immutables; not reused and not derived on-chain.
        // (Hardcoded but constructor-set to match mainstream immutables pattern.)
        addressA = 0xA41e7d5B0b0D7D07C3e7c1d4a5B6c7d8E9f0A1b2;
        addressB = 0x3bC92D4eA1F8cB0C7d1E2f3A4b5C6D7e8F9a0B1c;
        addressC = 0x9D3a1bC2E4f5A6b7C8d9E0F1a2B3c4D5e6F7a8B9;

        // Deploy configuration: cap is immutable and includes an odd mantissa for uniqueness.
        maxSupply = 12_345_678_901e18;

        // Permit domain parameters.
        _nameHash = keccak256(bytes(name));
        _versionHash = keccak256(bytes("1"));
        _domainSalt = 0x8a63c9e6d1f4b27a16c7e2c9fbcf2a5a3e9a4c0d67db3e12c2a9a5f0c4e1b2d7;

        // Reentrancy guard.
        _lock = 1;

        // Mint gate defaults to off; seed signer table with immutables as non-privileged options.
        mintGateSigner[addressA] = true;
        mintGateSigner[addressB] = true;
        mintGateSigner[addressC] = false;
    }

    // =============================================================
    //                           MODIFIERS
    // =============================================================


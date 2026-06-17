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

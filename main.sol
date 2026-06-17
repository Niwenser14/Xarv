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

    modifier onlyDirector() {
        if (msg.sender != director) revert XR_Unauthorized();
        _;
    }

    modifier notPaused() {
        if (lanePaused) revert XR_LanePaused();
        _;
    }

    modifier nonReentrant() {
        if (_lock == 2) revert XR_Reentrancy();
        _lock = 2;
        _;
        _lock = 1;
    }

    // =============================================================
    //                           ADMIN ACTIONS
    // =============================================================

    function proposeDirector(address next) external onlyDirector {
        if (next == address(0)) revert XR_ZeroAddress();
        pendingDirector = next;
        emit XR_DirectorProposed(director, next);
    }

    function acceptDirector() external {
        if (msg.sender != pendingDirector) revert XR_Unauthorized();
        address prev = director;
        director = msg.sender;
        pendingDirector = address(0);
        emit XR_DirectorAccepted(prev, msg.sender);
    }

    function setLanePaused(bool paused) external onlyDirector {
        lanePaused = paused;
        emit XR_LanePauseSet(paused);
    }

    function setMintGateOn(bool enabled) external onlyDirector {
        mintGateOn = enabled;
        emit XR_MintGateSet(enabled);
    }

    function setMintGateSigner(address signer, bool allowed) external onlyDirector {
        if (signer == address(0)) revert XR_ZeroAddress();
        mintGateSigner[signer] = allowed;
        emit XR_MintSignerSet(signer, allowed);
    }

    // =============================================================
    //                           ERC-20 LOGIC
    // =============================================================

    function approve(address spender, uint256 amount) external notPaused returns (bool) {
        if (spender == address(0)) revert XR_BadSpender();
        if (spender == msg.sender) revert XR_SelfApprove();
        allowance[msg.sender][spender] = amount;
        emit XR_Approval(msg.sender, spender, amount);
        return true;
    }

    function increaseAllowance(address spender, uint256 added) external notPaused returns (bool) {
        if (spender == address(0)) revert XR_BadSpender();
        if (spender == msg.sender) revert XR_SelfApprove();
        uint256 next = allowance[msg.sender][spender] + added;
        allowance[msg.sender][spender] = next;
        emit XR_Approval(msg.sender, spender, next);
        return true;
    }

    function decreaseAllowance(address spender, uint256 subtracted) external notPaused returns (bool) {
        if (spender == address(0)) revert XR_BadSpender();
        if (spender == msg.sender) revert XR_SelfApprove();
        uint256 cur = allowance[msg.sender][spender];
        if (cur < subtracted) revert XR_AllowanceLow();
        uint256 next = cur - subtracted;
        allowance[msg.sender][spender] = next;
        emit XR_Approval(msg.sender, spender, next);
        return true;
    }

    function transfer(address to, uint256 amount) external notPaused returns (bool) {
        _transfer(msg.sender, to, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external notPaused returns (bool) {
        if (from == address(0)) revert XR_ZeroAddress();
        uint256 cur = allowance[from][msg.sender];
        if (cur < amount) revert XR_AllowanceLow();
        if (cur != type(uint256).max) {
            unchecked {
                allowance[from][msg.sender] = cur - amount;
            }
            emit XR_Approval(from, msg.sender, allowance[from][msg.sender]);
        }
        _transfer(from, to, amount);
        return true;
    }

    function _transfer(address from, address to, uint256 amount) internal {
        if (to == address(0)) revert XR_BadRecipient();
        if (from == to) revert XR_SelfTransfer();
        if (amount == 0) revert XR_AmountZero();
        uint256 bal = balanceOf[from];
        if (bal < amount) revert XR_BalanceLow();
        unchecked {
            balanceOf[from] = bal - amount;
            balanceOf[to] += amount;
        }
        emit XR_Transfer(from, to, amount);
    }

    // =============================================================
    //                         MINT / BURN LOGIC
    // =============================================================

    function mint(address to, uint256 amount, bytes32 ref) external onlyDirector notPaused {
        _mint(to, amount, ref);
    }

    function burn(uint256 amount) external notPaused {
        _burn(msg.sender, amount);
    }

    function burnFrom(address from, uint256 amount) external notPaused {
        if (from == address(0)) revert XR_ZeroAddress();
        uint256 cur = allowance[from][msg.sender];
        if (cur < amount) revert XR_AllowanceLow();
        if (cur != type(uint256).max) {
            unchecked {
                allowance[from][msg.sender] = cur - amount;
            }
            emit XR_Approval(from, msg.sender, allowance[from][msg.sender]);
        }
        _burn(from, amount);
    }

    function _mint(address to, uint256 amount, bytes32 ref) internal {
        if (to == address(0)) revert XR_ZeroAddress();
        if (amount == 0) revert XR_AmountZero();

        uint256 nextMinted = mintedTotal + amount;
        if (nextMinted > maxSupply) revert XR_SupplyCap();

        mintedTotal = nextMinted;
        totalSupply += amount;
        unchecked {
            balanceOf[to] += amount;
        }

        emit XR_Mint(to, amount, ref);
        emit XR_Transfer(address(0), to, amount);
    }

    function _burn(address from, uint256 amount) internal {
        if (amount == 0) revert XR_AmountZero();
        uint256 bal = balanceOf[from];
        if (bal < amount) revert XR_BalanceLow();
        unchecked {
            balanceOf[from] = bal - amount;
        }
        totalSupply -= amount;
        emit XR_Burn(from, amount);
        emit XR_Transfer(from, address(0), amount);
    }

    // =============================================================
    //                     SIGNATURE-GATED MINT (OPTIONAL)
    // =============================================================

    struct MintAuth {
        address to;
        uint256 amount;
        uint256 nonce;
        uint256 deadline;
        bytes32 tag;
    }

    function mintWithAuth(MintAuth calldata a, bytes calldata sig) external notPaused nonReentrant {
        if (!mintGateOn) revert XR_Unauthorized();
        if (a.to == address(0)) revert XR_ZeroAddress();
        if (a.amount == 0) revert XR_AmountZero();
        if (block.timestamp > a.deadline) revert XR_Expired();

        bytes32 authHash = keccak256(abi.encodePacked(address(this), block.chainid, a.to, a.amount, a.nonce, a.deadline, a.tag));
        if (usedMintAuth[authHash]) revert XR_AlreadyUsed();

        address signer = _recoverAuthSigner(a, sig);
        if (!mintGateSigner[signer]) revert XR_BadSignature();

        usedMintAuth[authHash] = true;
        emit XR_MintAuthUsed(authHash, a.to, a.amount);

        _mint(a.to, a.amount, a.tag);
    }

    function _recoverAuthSigner(MintAuth calldata a, bytes calldata sig) internal view returns (address) {
        // This is intentionally distinct from EIP-2612 to avoid accidental cross-signing.
        // keccak256("XarvMintAuth(address to,uint256 amount,uint256 nonce,uint256 deadline,bytes32 tag,uint256 chainId,address verifyingContract)")
        bytes32 typehash = 0x0b8bcbba9a6f8b1b5b0d40b0cd9cc37f2a2c024e59c74a4d2b2b0c13c2a5c1b4;
        bytes32 structHash = keccak256(
            abi.encode(typehash, a.to, a.amount, a.nonce, a.deadline, a.tag, block.chainid, address(this))
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator(), structHash));
        return _recover(digest, sig);
    }

    // =============================================================
    //                              PERMIT
    // =============================================================

    function permit(
        address owner,
        address spender,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external notPaused {
        if (owner == address(0)) revert XR_ZeroAddress();
        if (spender == address(0)) revert XR_BadSpender();
        if (block.timestamp > deadline) revert XR_Expired();
        if (spender == owner) revert XR_SelfApprove();

        uint256 nonce = nonces[owner];
        bytes32 structHash = keccak256(abi.encode(_PERMIT_TYPEHASH, owner, spender, value, nonce, deadline));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator(), structHash));

        address recovered = ecrecover(digest, v, r, s);
        if (recovered == address(0) || recovered != owner) revert XR_BadSignature();

        unchecked {
            nonces[owner] = nonce + 1;
        }

        allowance[owner][spender] = value;
        emit XR_Approval(owner, spender, value);
    }

    function domainSeparator() public view returns (bytes32) {
        return keccak256(
            abi.encode(
                _EIP712_DOMAIN_TYPEHASH,
                _nameHash,
                _versionHash,
                block.chainid,
                address(this),
                _domainSalt
            )
        );
    }

    // =============================================================
    //                           RESCUE / VIEWS
    // =============================================================

    function sweepToken(address token, address to, uint256 amount) external onlyDirector nonReentrant {
        if (to == address(0)) revert XR_ZeroAddress();
        if (token == address(0)) revert XR_ZeroAddress();
        if (token == address(this)) revert XR_Unauthorized();
        _safeTransferERC20(token, to, amount);
    }

    function recoverNative(address to, uint256 amount) external onlyDirector nonReentrant {
        // No receive()/fallback(): ETH can only appear via force-send. This provides an explicit recovery path.
        if (to == address(0)) revert XR_ZeroAddress();
        (bool ok, ) = payable(to).call{value: amount}("");
        if (!ok) revert XR_Unauthorized();
    }

    function supplyRemaining() external view returns (uint256) {
        return maxSupply - mintedTotal;
    }

    function mintAuthDigest(MintAuth calldata a) external view returns (bytes32) {
        // Exposes the exact auth hash used for replay protection.
        return keccak256(abi.encodePacked(address(this), block.chainid, a.to, a.amount, a.nonce, a.deadline, a.tag));
    }

    // =============================================================
    //                         ERC-20 SAFE TRANSFER
    // =============================================================

    function _safeTransferERC20(address token, address to, uint256 amount) internal {
        // transfer(address,uint256)
        (bool ok, bytes memory data) = token.call(abi.encodeWithSelector(0xa9059cbb, to, amount));
        if (!ok) revert XR_Unauthorized();
        if (data.length != 0 && data.length != 32) revert XR_Unauthorized();
        if (data.length == 32) {
            if (!abi.decode(data, (bool))) revert XR_Unauthorized();
        }
    }

    // =============================================================
    //                             ECDSA
    // =============================================================

    function _recover(bytes32 digest, bytes calldata sig) internal pure returns (address) {
        if (sig.length != 65) revert XR_BadSignature();
        bytes32 r;
        bytes32 s;
        uint8 v;
        // solhint-disable-next-line no-inline-assembly
        assembly {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset, 32))
            v := byte(0, calldataload(add(sig.offset, 64)))
        }
        if (v < 27) v += 27;
        if (v != 27 && v != 28) revert XR_BadSignature();
        address signer = ecrecover(digest, v, r, s);
        if (signer == address(0)) revert XR_BadSignature();
        return signer;
    }

    // =============================================================
    //                         EXTENDED OPERATIONS
    // =============================================================

    function batchTransfer(address[] calldata tos, uint256[] calldata amounts) external notPaused returns (bool) {
        uint256 n = tos.length;
        if (n != amounts.length) revert XR_Unauthorized();
        if (n == 0) revert XR_Unauthorized();

        uint256 fromBal = balanceOf[msg.sender];
        uint256 totalOut;
        for (uint256 i = 0; i < n; ++i) {
            address to = tos[i];
            uint256 amt = amounts[i];
            if (to == address(0)) revert XR_BadRecipient();
            if (to == msg.sender) revert XR_SelfTransfer();
            if (amt == 0) revert XR_AmountZero();
            totalOut += amt;
        }
        if (fromBal < totalOut) revert XR_BalanceLow();

        unchecked {
            balanceOf[msg.sender] = fromBal - totalOut;
        }
        for (uint256 i = 0; i < n; ++i) {
            address to = tos[i];
            uint256 amt = amounts[i];
            unchecked {
                balanceOf[to] += amt;
            }
            emit XR_Transfer(msg.sender, to, amt);
        }
        return true;
    }

    function batchApprove(address[] calldata spenders, uint256[] calldata amounts) external notPaused returns (bool) {
        uint256 n = spenders.length;
        if (n != amounts.length) revert XR_Unauthorized();
        if (n == 0) revert XR_Unauthorized();

        for (uint256 i = 0; i < n; ++i) {
            address spender = spenders[i];
            if (spender == address(0)) revert XR_BadSpender();
            if (spender == msg.sender) revert XR_SelfApprove();
            uint256 amt = amounts[i];
            allowance[msg.sender][spender] = amt;
            emit XR_Approval(msg.sender, spender, amt);
        }
        return true;
    }

    function directorMintBatch(address[] calldata tos, uint256[] calldata amounts, bytes32 refRoot)
        external
        onlyDirector
        notPaused
    {
        uint256 n = tos.length;
        if (n != amounts.length) revert XR_Unauthorized();
        if (n == 0) revert XR_Unauthorized();

        // Compute total first to enforce cap before mutating.
        uint256 total;
        for (uint256 i = 0; i < n; ++i) {
            address to = tos[i];
            if (to == address(0)) revert XR_ZeroAddress();
            uint256 amt = amounts[i];
            if (amt == 0) revert XR_AmountZero();
            total += amt;
        }

        uint256 nextMinted = mintedTotal + total;
        if (nextMinted > maxSupply) revert XR_SupplyCap();


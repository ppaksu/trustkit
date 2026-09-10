// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title LogAnchor
/// @notice 오프체인 거절 로그의 머클 루트를 공개 기준점으로 고정한다.
/// @dev 검증자는 로그 서버를 신뢰하지 않는다. 특정 tree_size 의 루트를 이 컨트랙트에서
///      직접 읽어 inclusion proof 와 대조한다. 이벤트 로그 재생에 의존하지 않으려고
///      루트를 저장소에 둔다. 명세 5.0절과 8장 참조.
contract LogAnchor {
    // slot 0: owner(20B) + lastTreeSize(8B) 가 한 슬롯에 들어간다.
    address public owner;
    uint64 public lastTreeSize;

    address public immutable logOperator;

    /// @notice treeSize => 그 크기로 앵커된 머클 루트. 0 이면 해당 크기는 앵커되지 않았다.
    /// @dev submitRoot 가 영 루트를 거부하므로 0 은 부재를 뜻하는 값으로 안전하다.
    mapping(uint64 => bytes32) public rootByTreeSize;

    mapping(address => bool) public gatekeepers;

    event RootAnchored(uint64 indexed treeSize, bytes32 root);
    event GatekeeperSet(address indexed gatekeeper, bool allowed);

    error NotAuthorized();
    error TreeSizeNotIncreasing();
    error InvalidRoot();
    error InvalidAddress();

    constructor(address _logOperator) {
        if (_logOperator == address(0)) revert InvalidAddress();
        owner = msg.sender;
        logOperator = _logOperator;
    }

    /// @notice 트리 루트를 고정한다. treeSize 는 단조 증가만 허용한다.
    /// @dev 단조성 강제가 앵커 계층에서의 롤백을 막는다. 다만 컨트랙트는 두 루트 사이의
    ///      RFC 6962 consistency proof 를 검증하지 않는다. 그것은 검증자의 몫이다.
    function submitRoot(bytes32 root, uint64 treeSize) external {
        if (msg.sender != logOperator) revert NotAuthorized();
        if (root == bytes32(0) || treeSize == 0) revert InvalidRoot();
        if (treeSize <= lastTreeSize) revert TreeSizeNotIncreasing();
        rootByTreeSize[treeSize] = root;
        lastTreeSize = treeSize;
        emit RootAnchored(treeSize, root);
    }

    /// @notice 가장 최근에 고정된 기준점. 앵커가 없으면 (0, 0).
    function latestRoot() external view returns (uint64 treeSize, bytes32 root) {
        treeSize = lastTreeSize;
        root = rootByTreeSize[treeSize];
    }

    function setGatekeeper(address gk, bool allowed) external {
        if (msg.sender != owner) revert NotAuthorized();
        if (gk == address(0)) revert InvalidAddress();
        gatekeepers[gk] = allowed;
        emit GatekeeperSet(gk, allowed);
    }
}

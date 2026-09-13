// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title LogAnchor
/// @notice 오프체인 로그의 머클 루트를 공개 기준점으로 고정한다.
/// @dev 검증자는 로그 서버를 신뢰하지 않는다. 루트를 여기서 직접 읽어 포함 증명과
///      대조한다. 이벤트 재생에 의존하지 않으려고 저장소에 둔다.
contract LogAnchor {
    // owner(20B) + lastTreeSize(8B) 가 한 슬롯에 들어간다.
    address public owner;
    uint64 public lastTreeSize;

    address public immutable logOperator;

    /// @notice treeSize => 그 크기로 앵커된 루트. 0 이면 미앵커.
    /// @dev submitRoot 가 영 루트를 거부하므로 0 을 부재 값으로 써도 안전하다.
    mapping(uint64 => bytes32) public rootByTreeSize;

    mapping(address => bool) public gateways;

    event RootAnchored(uint64 indexed treeSize, bytes32 root);
    event GatewaySet(address indexed gateway, bool allowed);

    error NotAuthorized();
    error TreeSizeNotIncreasing();
    error InvalidRoot();
    error InvalidAddress();

    constructor(address _logOperator) {
        if (_logOperator == address(0)) revert InvalidAddress();
        owner = msg.sender;
        logOperator = _logOperator;
    }

    /// @notice 루트를 고정한다. logOperator 만 호출할 수 있고 treeSize 는 단조 증가다.
    /// @dev 단조성 한 줄이 롤백과 같은 크기 재앵커를 동시에 막는다.
    ///      consistency proof 는 검증하지 않는다. 검증자가 오프체인에서 한다.
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

    /// @notice 게이트웨이 레지스트리. 없으면 아무나 레코드를 발급할 수 있다.
    function setGateway(address gw, bool allowed) external {
        if (msg.sender != owner) revert NotAuthorized();
        if (gw == address(0)) revert InvalidAddress();
        gateways[gw] = allowed;
        emit GatewaySet(gw, allowed);
    }
}

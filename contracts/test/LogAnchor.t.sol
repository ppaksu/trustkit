// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/LogAnchor.sol";

contract LogAnchorTest is Test {
    LogAnchor a;
    address op = address(0xBEEF);
    address gk = address(0xCAFE);

    function setUp() public {
        a = new LogAnchor(op);
    }

    function test_onlyOperatorCanAnchor() public {
        vm.expectRevert(LogAnchor.NotAuthorized.selector);
        a.submitRoot(bytes32(uint256(1)), 1);
    }

    /// 배포자는 owner 지만 logOperator 가 아니다. 두 권한이 분리되어 있어야 한다.
    function test_ownerIsNotOperator() public {
        assertEq(a.owner(), address(this));
        vm.expectRevert(LogAnchor.NotAuthorized.selector);
        a.submitRoot(bytes32(uint256(1)), 1);
    }

    function test_monotonicTreeSize() public {
        vm.startPrank(op);
        a.submitRoot(bytes32(uint256(1)), 10);
        vm.expectRevert(LogAnchor.TreeSizeNotIncreasing.selector);
        a.submitRoot(bytes32(uint256(2)), 10); // 같은 크기 재앵커 불가
        vm.expectRevert(LogAnchor.TreeSizeNotIncreasing.selector);
        a.submitRoot(bytes32(uint256(3)), 9); // 롤백 불가
        a.submitRoot(bytes32(uint256(4)), 11);
        vm.stopPrank();
        assertEq(a.lastTreeSize(), 11);
    }

    /// 한 번 고정된 루트는 덮어쓸 수 없다. 단조성이 이를 보장한다.
    function test_anchoredRootIsImmutable() public {
        vm.startPrank(op);
        a.submitRoot(bytes32(uint256(0xAA)), 8);
        vm.expectRevert(LogAnchor.TreeSizeNotIncreasing.selector);
        a.submitRoot(bytes32(uint256(0xBB)), 8);
        vm.stopPrank();
        assertEq(a.rootByTreeSize(8), bytes32(uint256(0xAA)));
    }

    function test_rejectsZeroRootAndZeroSize() public {
        vm.startPrank(op);
        vm.expectRevert(LogAnchor.InvalidRoot.selector);
        a.submitRoot(bytes32(0), 1);
        vm.expectRevert(LogAnchor.InvalidRoot.selector);
        a.submitRoot(bytes32(uint256(1)), 0);
        vm.stopPrank();
    }

    /// 검증 5단계가 쓰는 조회. 앵커되지 않은 크기는 0 을 돌려준다.
    function test_rootByTreeSize() public {
        vm.startPrank(op);
        a.submitRoot(bytes32(uint256(0xAA)), 8);
        a.submitRoot(bytes32(uint256(0xBB)), 16);
        vm.stopPrank();
        assertEq(a.rootByTreeSize(8), bytes32(uint256(0xAA)));
        assertEq(a.rootByTreeSize(16), bytes32(uint256(0xBB)));
        assertEq(a.rootByTreeSize(12), bytes32(0));
        assertEq(a.rootByTreeSize(0), bytes32(0));
    }

    function test_latestRoot() public {
        (uint64 t0, bytes32 r0) = a.latestRoot();
        assertEq(t0, 0);
        assertEq(r0, bytes32(0));

        vm.prank(op);
        a.submitRoot(bytes32(uint256(0xCC)), 32);
        (uint64 t1, bytes32 r1) = a.latestRoot();
        assertEq(t1, 32);
        assertEq(r1, bytes32(uint256(0xCC)));
    }

    function test_gatekeeperRegistry() public {
        a.setGatekeeper(gk, true);
        assertTrue(a.gatekeepers(gk));
        // 운영자는 레지스트리를 못 바꾼다
        vm.prank(op);
        vm.expectRevert(LogAnchor.NotAuthorized.selector);
        a.setGatekeeper(gk, false);
    }

    function test_gas_submitRoot() public {
        vm.startPrank(op);
        a.submitRoot(bytes32(uint256(1)), 100); // 워밍업
        uint256 g = gasleft();
        a.submitRoot(bytes32(uint256(2)), 200);
        uint256 used = g - gasleft();
        vm.stopPrank();
        emit log_named_uint("submitRoot gas (steady state)", used);
        assertLt(used, 30000);
    }
}

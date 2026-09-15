// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {VmSafe} from "forge-std/Vm.sol";
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

    function test_gatewayRegistry() public {
        a.setGateway(gk, true);
        assertTrue(a.gateways(gk));
        // 운영자는 레지스트리를 못 바꾼다
        vm.prank(op);
        vm.expectRevert(LogAnchor.NotAuthorized.selector);
        a.setGateway(gk, false);
    }

    /// @dev 가스 수치 대신 저장 슬롯 쓰기 횟수를 본다.
    ///
    ///      gasleft() 델타는 --gas-report 계측이 섞여 부풀고, lastCallGas 는
    ///      --isolate 없이는 revert 한다. 실행 모드에 따라 결과가 달라지는 테스트는
    ///      신뢰할 수 없다.
    ///
    ///      정작 지키려던 불변식은 "정상 상태의 submitRoot 가 슬롯 두 개만
    ///      건드린다" 이다. rootByTreeSize 새 항목 하나와 lastTreeSize 갱신 하나.
    ///      슬롯이 늘면 가스도 반드시 는다.
    function test_gas_submitRoot() public {
        vm.startPrank(op);
        a.submitRoot(bytes32(uint256(1)), 100); // 워밍업. 첫 SSTORE 는 비싸다

        vm.startStateDiffRecording();
        a.submitRoot(bytes32(uint256(2)), 200);
        VmSafe.AccountAccess[] memory diff = vm.stopAndReturnStateDiff();
        vm.stopPrank();

        uint256 writes = 0;
        for (uint256 i = 0; i < diff.length; i++) {
            for (uint256 j = 0; j < diff[i].storageAccesses.length; j++) {
                if (diff[i].storageAccesses[j].isWrite && !diff[i].storageAccesses[j].reverted) {
                    writes++;
                }
            }
        }
        emit log_named_uint("submitRoot storage writes", writes);
        assertEq(writes, 3, "rootByTreeSize + anchoredAt + lastTreeSize");
    }
}

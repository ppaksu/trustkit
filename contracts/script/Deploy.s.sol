// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Script.sol";
import "../src/LogAnchor.sol";

/// 배포. LOG_OPERATOR 는 LogAck 에 서명하는 계정이며 배포 후 바꿀 수 없다.
contract Deploy is Script {
    function run() external returns (LogAnchor anchor) {
        address operator = vm.envAddress("LOG_OPERATOR");
        vm.startBroadcast();
        anchor = new LogAnchor(operator);
        vm.stopBroadcast();
        console2.log("LogAnchor deployed:", address(anchor));
        console2.log("logOperator:", operator);
    }
}

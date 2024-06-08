// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.12;

import {OwnableUpgradeable} from "@openzeppelin-upgrades/contracts/access/OwnableUpgradeable.sol";
import {ECDSAUpgradeable} from "@openzeppelin-upgrades/contracts/utils/cryptography/ECDSAUpgradeable.sol";

import {IAVSDirectory} from "@eigenlayer/contracts/interfaces/IAVSDirectory.sol";
import {ECDSAStakeRegistry, Quorum, StrategyParams, IDelegationManager, ISignatureUtils, IStrategy} from "@eigenlayer-middleware/src/unaudited/ECDSAStakeRegistry.sol";

import {HelloWorldServiceManager, IHelloWorldServiceManager} from "../src/HelloWorldServiceManager.sol";

import "forge-std/Test.sol";
import "forge-std/console.sol";

contract HelloWorldTaskManagerTest is Test {

    using ECDSAUpgradeable for bytes32;

    string public taskName;

    uint256 public operatorPK;
    uint256 public taskCreatedBlock;

    address public owner;
    address public operator;

    ECDSAStakeRegistry public stakeRegistry;
    HelloWorldServiceManager public serviceManager;

    IAVSDirectory public constant avsDirectory = IAVSDirectory(0x135DDa560e946695d6f155dACaFC6f1F25C1F5AF);
    IDelegationManager public constant delegationManager = IDelegationManager(0x39053D51B77DC0d36036Fc1fCc8Cb819df8Ef37A);
    IStrategy public constant sfrxETHStrategy = IStrategy(0x8CA7A5d6f3acd3A7A8bC468a8CD0FB14B6BD28b6);

    function setUp() public {
        vm.selectFork(vm.createFork(vm.envString("ETHEREUM_RPC_URL")));

        // initialize owner
        owner = _createUser("owner");

        // initialize operator
        (operator, operatorPK) = makeAddrAndKey("operator");
        vm.deal({ account: operator, newBalance: 100 ether });

        // deploy the stake registry
        stakeRegistry = new ECDSAStakeRegistry(delegationManager);

        // deploy the service manager
        serviceManager = new HelloWorldServiceManager(address(avsDirectory), address(stakeRegistry), address(delegationManager), owner);

        // initialize the stake registry
        StrategyParams[] memory _quorumsStrategyParams = new StrategyParams[](1);
        _quorumsStrategyParams[0] = StrategyParams(
            sfrxETHStrategy,
            uint96(10_000)
        );
        
        Quorum memory _quorum = Quorum(
            _quorumsStrategyParams
        );

        vm.prank(owner);
        stakeRegistry.initialize(
            address(serviceManager),
            1, // _thresholdWeight
            _quorum
        );
        assertEq(stakeRegistry.owner(), owner, "setUp: E0");

        // label contract instances
        vm.label({ account: address(stakeRegistry), newLabel: "stakeRegistry" });
        vm.label({ account: address(serviceManager), newLabel: "serviceManager" });
        vm.label({ account: address(avsDirectory), newLabel: "avsDirectory" });
        vm.label({ account: address(delegationManager), newLabel: "delegationManager" });
        vm.label({ account: address(sfrxETHStrategy), newLabel: "sfrxETHStrategy" });
    }

    // 1. register the service manager with EL's AVS directory
    function testRegisterAVS() public {
        string memory _metadataURI = "https://avs.com/metadata.json";

        vm.prank(owner);
        serviceManager.updateAVSMetadataURI(_metadataURI);
    }

    // 2. register an operator to EigenLayer
    function testRegisterOperatorToEigenLayer() public {
        testRegisterAVS();

        IDelegationManager.OperatorDetails memory _operatorDetails = IDelegationManager.OperatorDetails({
            earningsReceiver: operator,
            delegationApprover: address(0),
            stakerOptOutWindowBlocks: 0
        });

        string memory _metadataURI = "https://operator.com/metadata.json";

        vm.prank(operator);
        delegationManager.registerAsOperator(_operatorDetails, _metadataURI);

        assertEq(delegationManager.isOperator(operator), true, "testRegisterOperatorToEigenLayer: E0");
    }

    // 3. register an operator to the AVS
    function testRegisterOperatorToAVS() public {
        testRegisterOperatorToEigenLayer();

        bytes32 _salt = _generateRandomSalt();
        uint256 _expiry = block.timestamp + 1 hours;

        ISignatureUtils.SignatureWithSaltAndExpiry memory _operatorSignature = ISignatureUtils.SignatureWithSaltAndExpiry({
            signature: "",
            salt: _salt,
            expiry: _expiry
        });

        bytes32 _digestHash = avsDirectory.calculateOperatorAVSRegistrationDigestHash(
            operator,
            address(serviceManager),
            _salt,
            _expiry
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(operatorPK, _digestHash);
        _operatorSignature.signature = abi.encodePacked(r, s, v);

        stakeRegistry.registerOperatorWithSignature(
            operator,
            _operatorSignature
        );
    }

    // 4. create a new task
    function testCreateNewTask() public {
        testRegisterOperatorToAVS();

        taskName = "YieldNest";
        taskCreatedBlock = block.number;

        serviceManager.createNewTask(taskName);
    }

    // 5. respond to a task
    function testRespondToTask() public {
        testCreateNewTask();

        IHelloWorldServiceManager.Task memory _task = IHelloWorldServiceManager.Task({
            name: taskName,
            taskCreatedBlock: uint32(taskCreatedBlock)
        });

        uint32 _referenceTaskIndex = 0;

        bytes32 _messageHash = keccak256(abi.encodePacked("Hello, ", taskName));
        bytes32 _ethSignedMessageHash = _messageHash.toEthSignedMessageHash();


        (uint8 v, bytes32 r, bytes32 s) = vm.sign(operatorPK, _ethSignedMessageHash);
        bytes memory _signature = abi.encodePacked(r, s, v);

        vm.expectEmit(address(serviceManager));
        emit IHelloWorldServiceManager.TaskResponded(_referenceTaskIndex, _task, operator);

        vm.prank(operator);
        serviceManager.respondToTask(_task, _referenceTaskIndex, _signature);
    }

    // ============================================================================================
    // Internal helpers
    // ============================================================================================

    function _createUser(string memory _name) internal returns (address payable) {
        address payable _user = payable(makeAddr(_name));
        vm.deal({ account: _user, newBalance: 100 ether });
        return _user;
    }

    function _generateRandomSalt() internal view returns (bytes32) {
        return keccak256(abi.encodePacked(block.timestamp, block.difficulty));
    }
}
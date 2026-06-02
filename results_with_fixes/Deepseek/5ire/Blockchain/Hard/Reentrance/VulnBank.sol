// SPDX-License-Identifier: MIT
pragma solidity ^0.6.12;

contract VulnBank {
    mapping(address => uint) public balances;
    address public owner;
    address public target;
    string private flag;
    bool public revealed;

    event Deposit(address indexed who, uint amount);
    event Withdraw(address indexed who, uint amount);
    event FlagRevealed(string flag);

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner");
        _;
    }

    constructor(address _target) public {
        owner = msg.sender;
        target = _target;
        revealed = false;
    }

    function setFlag(string memory _flag) external onlyOwner {
        flag = _flag;
    }

    function setTarget(address _target) external onlyOwner {
        target = _target;
    }

    function deposit() public payable {
        balances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    function withdraw(uint amount) public {
        require(balances[msg.sender] >= amount, "Insufficient funds available");

        (bool sent, ) = msg.sender.call{value: amount}("");
        balances[msg.sender] -= amount;

        require(sent, "Transfer failed");

        if (!revealed && address(this).balance == 0) {
            revealed = true;
            emit FlagRevealed(flag);
        }
    }

    function getFlag() external view returns (string memory) {
        require(revealed, "Flag not revealed yet");
        return flag;
    }

    receive() external payable {}
}
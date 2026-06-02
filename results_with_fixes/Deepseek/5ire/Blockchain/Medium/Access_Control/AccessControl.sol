pragma solidity ^0.8.0;

contract AccessControl {
    address public owner;
    string private flag;
    
    bool public revealed;

    event OwnerChanged(address indexed oldOwner, address indexed newOwner);
    event FlagRevealed(string flag);

    constructor(string memory _flag) {
        owner = msg.sender;
        flag = _flag;
        revealed = false;
    }

    function changeOwner(address _newOwner) public {
        address oldOwner = owner;
        owner = _newOwner;
        emit OwnerChanged(oldOwner, _newOwner);
    }

    function solve() public {
        require(msg.sender == owner, "Only the owner can get the flag.");
        
        if (!revealed) {
            revealed = true;
            emit FlagRevealed(flag);
        }
    }

    function getFlag() public view returns (string memory) {
        require(revealed, "Challenge not yet solved!");
        return flag;
    }
}
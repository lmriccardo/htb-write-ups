// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Creature} from "./Creature.sol";

contract Solve {
    Creature public creature;
    
    constructor (Creature _creature) {
        creature = _creature;
    }
    
    function f(uint256 _damage) external {
        creature.attack(_damage);
    }
}
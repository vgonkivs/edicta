// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

/// Publication sink for Evolve rollups. The calldata of publish is the
/// payload; the rollup's data blob on Celestia is what proves it was public.
/// The event is a convenience for indexers and is never part of a proof.
/// No storage, no owner, no value: calls with ETH revert (non-payable, no
/// receive or fallback).
contract EdictaPublish {
    event EdictaPayload(bytes32 indexed payloadHash);

    function publish(bytes calldata blob) external {
        emit EdictaPayload(sha256(blob));
    }
}

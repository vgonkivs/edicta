// SPDX-License-Identifier: Apache-2.0

// Package anchor reads and checks Celestia anchors: the PayForBlobs of a
// da = 2 intent, and the PayForFibre anchor of a da = 1 reference with its
// proof from the block's namespace data and its validator certificate. The
// gate's chain adapter, the Recorder, the inclusion and the absence checks
// share it.
package anchor

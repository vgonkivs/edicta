// SPDX-License-Identifier: Apache-2.0

package eden

// ResetDeprecationLog lets a test see the once-per-process log line again.
func ResetDeprecationLog() { deprecationLogged.Store(false) }

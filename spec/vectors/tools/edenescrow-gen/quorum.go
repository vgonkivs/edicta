// SPDX-License-Identifier: Apache-2.0

package main

// The multi-source outcome table of the settlement check (sections 5.3 and
// 7.4): per-source results are abstract, the vector pins how they combine.

type qsrc struct {
	host, operator, result, outcome, binding, reason string
}

type qcase struct {
	id, desc        string
	minLevel, phase string
	minSources      uint64
	sources         []qsrc
}

type qresult struct {
	status, reason, level, outcome, await string
	s10, s11, release                     bool
}

func pass(host, op, outcome, binding string) qsrc {
	return qsrc{host: host, operator: op, result: "pass", outcome: outcome, binding: binding}
}

func res(host, op, result string) qsrc { return qsrc{host: host, operator: op, result: result} }

func aside(host, op, reason string) qsrc {
	return qsrc{host: host, operator: op, result: "set_aside", reason: reason}
}

func reasonOf(s qsrc) string {
	switch s.result {
	case "not_found":
		return "settlement_not_found"
	case "unavailable":
		return "settlement_source_unavailable"
	case "unconfirmed":
		return "settlement_unconfirmed"
	case "set_aside":
		return s.reason
	}
	panic("reason of " + s.result)
}

func rank(level string) int {
	switch level {
	case "L0":
		return 0
	case "L1":
		return 1
	}
	return -1
}

func quorum(c qcase) qresult {
	var passes []qsrc
	unconfirmed := false
	for _, s := range c.sources {
		switch s.result {
		case "pass":
			passes = append(passes, s)
		case "unconfirmed":
			unconfirmed = true
		}
	}
	for _, p := range passes[min(1, len(passes)):] {
		if p.binding != passes[0].binding {
			return qresult{status: "unchecked", reason: "settlement_disagree", await: "disputed"}
		}
	}
	distinct := func(want string) int {
		seen := map[string]bool{}
		for _, s := range c.sources {
			if s.result == want {
				seen[s.operator] = true
			}
		}
		return len(seen)
	}
	k := distinct("pass")
	reached := ""
	switch {
	case k >= int(c.minSources):
		reached = "L1"
	case k >= 1:
		reached = "L0"
	}
	if reached != "" && rank(reached) >= rank(c.minLevel) {
		o := passes[0].outcome
		return qresult{status: "pass", level: reached, outcome: o, await: o,
			s10: true, s11: o == "executed" && reached == "L1"}
	}
	r := qresult{status: "unchecked"}
	switch {
	case unconfirmed:
		r.reason = "settlement_unconfirmed"
	case k >= 1:
		r.reason = "settlement_below_level"
	default:
		r.reason = reasonOf(c.sources[0])
	}
	switch {
	case c.phase == "polling":
		r.await = "pending"
	case k == 0 && !unconfirmed && distinct("not_found") >= int(c.minSources):
		r.await, r.release = "not_executed", true
	default:
		r.await = "unknown"
	}
	return r
}

func quorumCases() []qcase {
	const (
		own = "own-node.example"
		gw  = "rpc.eden.gateway.fm"
		bs  = "eden.blockscout.com"
	)
	two := func(id, desc, phase string, a, b qsrc) qcase {
		return qcase{id: id, desc: desc, minLevel: "L1", phase: phase, minSources: 2, sources: []qsrc{a, b}}
	}
	return []qcase{
		two("agree_executed", "Two operators serve the deposit in the same block with status 1.", "polling",
			pass(own, "own", "executed", "B1"), pass(gw, "gateway", "executed", "B1")),
		two("agree_reverted", "Two operators agree on a reverted deposit: recorded, but no Payment-Signature.", "polling",
			pass(own, "own", "reverted", "B1"), pass(gw, "gateway", "reverted", "B1")),
		two("disagree_block", "Two operators serve the transaction in different blocks (a rollback or a lie).", "polling",
			pass(own, "own", "executed", "B1"), pass(gw, "gateway", "executed", "B2")),
		two("disagree_status", "Same block, one says status 1, the other status 0 (receipt encodings differ).", "until_passed",
			pass(own, "own", "executed", "B1"), pass(gw, "gateway", "reverted", "B1r")),
		two("one_found_one_not_found", "One operator has it, the other not yet: below the level, keep polling.", "polling",
			pass(own, "own", "executed", "B1"), res(gw, "gateway", "not_found")),
		two("one_found_one_not_found_until", "The same at until: never not_executed while a source shows the deposit.", "until_passed",
			pass(own, "own", "executed", "B1"), res(gw, "gateway", "not_found")),
		two("one_found_one_unconfirmed", "One operator past ConfirmDepth, the other below it.", "polling",
			pass(own, "own", "executed", "B1"), res(gw, "gateway", "unconfirmed")),
		two("same_operator", "Two hosts of one operator count once.", "polling",
			pass(gw, "gateway", "executed", "B1"), pass("rpc2.eden.gateway.fm", "gateway", "executed", "B1")),
		{id: "two_of_three", desc: "Two operators agree, the third has not seen it: the level is reached.", minLevel: "L1", phase: "polling", minSources: 2,
			sources: []qsrc{pass(own, "own", "executed", "B1"), res(bs, "blockscout", "not_found"), pass(gw, "gateway", "executed", "B1")}},
		{id: "two_agree_third_disagrees", desc: "Two agree, a third passing source names another block: any disagreement between passing sources wins.", minLevel: "L1", phase: "polling", minSources: 2,
			sources: []qsrc{pass(own, "own", "executed", "B1"), pass(gw, "gateway", "executed", "B1"), pass(bs, "blockscout", "executed", "B2")}},
		{id: "three_required_two_agree", desc: "MinSources 3 and two agreeing operators: below the level.", minLevel: "L1", phase: "polling", minSources: 3,
			sources: []qsrc{pass(own, "own", "executed", "B1"), pass(gw, "gateway", "executed", "B1"), res(bs, "blockscout", "unavailable")}},
		two("none_found_polling", "Neither operator has it yet.", "polling",
			res(own, "own", "not_found"), res(gw, "gateway", "not_found")),
		two("none_found_until", "Neither operator has it at until: not_executed, the nonce may be released.", "until_passed",
			res(own, "own", "not_found"), res(gw, "gateway", "not_found")),
		two("none_found_same_operator_until", "Both answers come from one operator: unknown, not not_executed.", "until_passed",
			res(gw, "gateway", "not_found"), res("rpc2.eden.gateway.fm", "gateway", "not_found")),
		two("not_found_and_unavailable_until", "One not found, one down: unknown; the reason is the first source's.", "until_passed",
			res(own, "own", "not_found"), res(gw, "gateway", "unavailable")),
		two("unavailable_first_until", "One down, one not found: the first source's reason.", "until_passed",
			res(own, "own", "unavailable"), res(gw, "gateway", "not_found")),
		two("not_found_and_unconfirmed_until", "One below ConfirmDepth at until: unknown, retried later.", "until_passed",
			res(own, "own", "not_found"), res(gw, "gateway", "unconfirmed")),
		two("pass_and_code_mismatch", "The second source serves other code at the escrow address and is set aside.", "until_passed",
			pass(own, "own", "executed", "B1"), aside(gw, "gateway", "settlement_code_mismatch")),
		two("both_set_aside_until", "Both sources set aside (chain id, then hash): the first reason.", "until_passed",
			aside(own, "own", "settlement_chain_config"), aside(gw, "gateway", "settlement_hash_mismatch")),
		{id: "level_l0_single", desc: "MinLevel L0 (explicit configuration): one operator suffices for the report and the record, never for a Payment-Signature.", minLevel: "L0", phase: "polling", minSources: 2,
			sources: []qsrc{pass(own, "own", "executed", "B1"), res(gw, "gateway", "not_found")}},
		{id: "level_l0_two_agree", desc: "MinLevel L0 with two agreeing operators: the report gives the highest level reached.", minLevel: "L0", phase: "polling", minSources: 2,
			sources: []qsrc{pass(own, "own", "executed", "B1"), pass(gw, "gateway", "executed", "B1")}},
	}
}

func buildQuorumFile() obj {
	var cs []any
	for _, c := range quorumCases() {
		var ss []any
		for _, s := range c.sources {
			e := obj{{"host", s.host}, {"operator", s.operator}, {"result", s.result}}
			if s.result == "pass" {
				e = append(e, kv{"outcome", s.outcome}, kv{"binding", s.binding})
			}
			if s.result == "set_aside" {
				e = append(e, kv{"reason", s.reason})
			}
			ss = append(ss, e)
		}
		r := quorum(c)
		v := obj{{"status", r.status}}
		if r.status == "pass" {
			v = append(v, kv{"level", r.level}, kv{"outcome", r.outcome})
		} else {
			v = append(v, kv{"reason", r.reason})
		}
		cs = append(cs, obj{
			{"id", c.id}, {"description", c.desc},
			{"min_level", c.minLevel}, {"min_sources", dec(c.minSources)}, {"phase", c.phase},
			{"sources", ss},
			{"verify", v},
			{"await", r.await},
			{"record_allowed", r.s10}, {"payment_signature_allowed", r.s11}, {"nonce_release_allowed", r.release},
		})
	}
	return obj{
		{"format", format}, {"profile", profile}, {"revision", revision}, {"generator", generator},
		{"source_results", []string{"pass", "not_found", "unconfirmed", "unavailable", "set_aside"}},
		{"binding_note", "binding labels stand for (blockHash, transactionIndex, receipt consensus encoding); equal labels mean byte-equal values"},
		{"cases", cs},
	}
}

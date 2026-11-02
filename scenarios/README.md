# MCP-SoK Scenario Registry

**Total: 45 scenarios**

## Scenario Table

| # | Scenario | Attack Class | Taxonomy Class | Oracles | Prior Work |
|---|----------|-------------|---------------|---------|------------|
| 1 | tool-poisoning-exfiltration | tool-poisoning | P1 | network, exfiltration | Invariant Labs 2025 |
| 2 | tool-poisoning-file-read | tool-poisoning | P1 | file_access, exfiltration | Invariant Labs 2025 |
| 3 | cross-tool-reference | tool-poisoning | P7 | network, exfiltration | MCPTox (AAAI 2026) |
| 4 | cross-tool-reference-compliance | tool-poisoning | P7 | network | MCPTox + compliance framing |
| 5 | cross-tool-reference-valuesafe | tool-poisoning | P7 | network | MCPTox + ethical framing |
| 6 | encoded-description-injection | tool-poisoning | P3 | network | CipherChat (Yuan 2024) |
| 7 | obfuscated-base64-exfil | tool-poisoning | P3 | network, exfiltration | CipherChat + base64 |
| 8 | fake-completion-prefix | tool-poisoning | P5 | network | Greshake 2023 |
| 9 | persona-override-injection | tool-poisoning | P5 | network | Greshake 2023 |
| 10 | virtual-context-escape | tool-poisoning | P5 | network | ChatInject (2509.22830) |
| 11 | language-switch-injection | tool-poisoning | P4 | network | HackAPrompt |
| 12 | language-switch-compliance | tool-poisoning | P4 | network | HackAPrompt + compliance |
| 13 | payload-splitting | tool-poisoning | P13 | network | Novel (mcpvenom) |
| 14 | conditional-trigger | tool-poisoning | P12 | file_access, network | Novel (mcpvenom) |
| 15 | schema-parameter-coercion | tool-poisoning | P2 | exfiltration | OWASP MCP03:2025 |
| 16 | tool-response-injection | tool-poisoning | P6 | network, exfiltration | MCPTox result-only |
| 17 | tool-result-identity-injection | tool-poisoning | P6 | network | MCPTox + identity |
| 18 | mcp-resource-uri-poisoning | tool-poisoning | P14 | network | arXiv 2506.02040 |
| 19 | rug-pull-redefinition | tool-poisoning (2-phase) | P8 | file_access, network | Bhatt et al. IEEE CARS 2025 |
| 20 | authority-role-spoofing | confused-deputy | P10 | unauthorized_action, network | ChatInject |
| 21 | confused-deputy-chain | confused-deputy | P10 | file_access, exfiltration | InjecAgent 2024 |
| 22 | privilege-escalation-chain | confused-deputy | P10 | unauthorized_action, file_access | InjecAgent 2024 |
| 23 | memory-poisoning-delayed | memory-poisoning | P9 | network, exfiltration | Crescendo |
| 24 | crescendo-escalation | memory-poisoning (3-phase) | P9 | network | Russinovich 2024 |
| 25 | gradual-kill-chain | memory-poisoning (3-phase) | P9 | network, file_access | Novel (mcpvenom) |
| 26 | rag-document-poisoning | memory-poisoning | P9 | network, exfiltration, file_access | Greshake 2023 |
| 27 | cross-agent-delegation | cross-agent-injection | P11 | network, exfiltration | InjecAgent direct |
| 28 | schema-field-tpa | tool-poisoning | P2 | network, exfiltration | OWASP MCP03 — param desc |
| 29 | invisible-unicode-tpa | tool-poisoning | P3 | network | Zero-width steganography |
| 30 | fake-prior-turn-priming | tool-poisoning | P5 | network, exfiltration | AAAI 2026 context-priming |
| 31 | stacked-cipher-tpa | tool-poisoning | P3 | network | SEAL/Cryptex stacked cipher |
| 32 | tool-name-injection | tool-poisoning | P1 | network | Novel — tool name surface |
| 33 | mcp-result-persistence | memory-poisoning (2-phase) | P9 | network | Framework memory exploit |
| 34 | resource-content-injection | tool-poisoning | P14 | network | MCP resource content |
| 35 | multi-tool-chain-poisoning | tool-poisoning | P13 | network, exfiltration | 3-way payload splitting |
| 36 | annotation-hint-injection | annotation-injection | P16 | network, exfiltration | Novel — no prior work on annotation metadata injection |
| 37 | unicode-bidi-poisoning | unicode-encoding | P17 | network, exfiltration | BiDi/Unicode Tags steganography (CSA 2026; arXiv:2607.05744; arXiv:2505.16765) |
| 38 | streaming-response-injection | streaming-injection | P18 | network, exfiltration | Novel — no prior work on late-chunk injection in tools/call streaming |
| 39 | version-downgrade-legacy-exec | authority-spoofing | P5 | file_access, network, exfiltration | Static legacy-mode authority marker in tool description (CWE-290); no protocol negotiation occurs |
| 40 | parameter-binding-injection | parameter-binding | P20 | network, exfiltration | Parameter-name injection (HiddenLayer 2025); extends to default values |
| 41 | notification-channel-injection | notification-injection | P21 | network, exfiltration | Novel — no prior work on MCP notification channel injection |
| 42 | semantic-tool-shadowing | semantic-shadowing | P22 | network, exfiltration | Semantic equiv. selection vector (Hou et al. ACM TOSEM 2025; Bhatt et al. IEEE CARS 2025) |
| 43 | long-context-dilution | long-context-dilution | P23 | network, exfiltration | Long-context burial (Many-Shot Jailbreaking NeurIPS 2024; arXiv:2505.19773) |
| 44 | cross-phase-persistence | cross-phase-persistence | P24 | network, exfiltration | Cross-phase planting via tool result (arXiv:2606.04425) |
| 45 | dynamic-tool-registration | dynamic-registration | P25 | network, file_access, exfiltration | Dynamic registration exploit (novel — no prior work) |

## Attack Class Distribution

Authoritative source: `mcpvenom.scenarios.load_all_scenarios()`; counts below reflect the
locked scenario set (45 scenarios).

| Attack Class | Count | Taxonomy Classes |
|-------------|:-----:|-----------------|
| tool-poisoning | 26 | P1–P8, P12–P14 |
| memory-poisoning | 5 | P9 |
| confused-deputy | 3 | P10 |
| authority-spoofing | 1 | P5 |
| cross-agent-injection | 1 | P11 |
| annotation-injection | 1 | P16 |
| unicode-encoding | 1 | P17 |
| streaming-injection | 1 | P18 |
| parameter-binding | 1 | P20 |
| notification-injection | 1 | P21 |
| semantic-shadowing | 1 | P22 |
| long-context-dilution | 1 | P23 |
| cross-phase-persistence | 1 | P24 |
| dynamic-registration | 1 | P25 |

## Oracle Type Distribution

| Oracle Type | Count |
|------------|:-----:|
| network | 40 |
| exfiltration | 24 |
| file_access | 10 |
| unauthorized_action | 2 |

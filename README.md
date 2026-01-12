# GenAI Security Code Analysis

**Testing the Boundaries of Generative AI in Producing Secure Authentication Code**

## Overview

This project demonstrates that **GenAI should never be blindly trusted to produce secure code**. We prompted an AI model (Gemini 3 Flash Agent) to generate a production-ready authentication library for a cryptocurrency wallet application, then performed a comprehensive security analysis of the output.

## Project Structure

```
├── auth_lib/           # AI-generated authentication library
├── SECURITY_ANALYSIS.md    # Detailed security analysis (Markdown)
├── SECURITY_ANALYSIS.tex   # Detailed security analysis (LaTeX)
└── requirements.txt
```

## Key Findings

Despite explicit security requirements, the AI-generated code contains critical vulnerabilities:

| Finding | Severity |
|---------|----------|
| Hardcoded cryptographic keys in source code | ❌ Critical |
| Missing role-based access control (RBAC) | ❌ Critical |
| Incomplete exception handling | ⚠️ Medium |
| No password rehashing on parameter updates | ⚠️ Medium |
| Missing rate limiting on password reset | ⚠️ Medium |

## Conclusion

While GenAI can produce functional code that *appears* secure, it consistently misses subtle but critical security details. **Human security review remains essential.**

---

*Securing Digital Products and Services — Homework 1*  
*Aya Darawshi (323964676) & Ibrahim Abomokh (315270678)*

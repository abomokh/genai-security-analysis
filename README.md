# GenAI Security Code Analysis

**Testing the Boundaries of Generative AI in Producing Secure Authentication Code**

> ## ***This was NOT written by AI, so take your time reading it :)***

## Overview

This project demonstrates that **GenAI should never be blindly trusted to produce secure code**. We prompted an AI model (Gemini 3 Flash Agent) to generate a production-ready authentication library for a cryptocurrency wallet application, then performed a comprehensive security analysis of the output.

**Note that the security analysis was not written by GenAI, but used GenAI to ensure completeness (and fix grammar issues of course)**

## Project Structure

```
├── auth_lib/                                 # AI-generated authentication library
├── prompt.md                                 # The prompt we gave to the AI
├── AI_Response.md                            # The AI's response and reasoning
├── Security Analysis of Generated Code.pdf  # Our detailed security analysis
└── requirements.txt
```

## Methodology

1. **Prompt Engineering**: We crafted a detailed prompt (`prompt.md`) specifying strict security requirements for a cryptocurrency wallet authentication system
2. **AI Generation**: Gemini 3 Flash Agent generated the complete `auth_lib/` implementation (`AI_Response.md`)
3. **Security Audit**: We manually analyzed the generated code against the requirements and security best practices

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

While GenAI can produce functional code that *appears* secure, it consistently misses subtle but critical security details. **Human security review remains essential, as well as proper prompting**

---

*Securing Digital Products and Services*  
*Aya Darawshi & Ibrahim Abomokh*

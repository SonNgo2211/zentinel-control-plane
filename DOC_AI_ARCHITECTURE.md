# Zentinel AI Security Architecture

Zentinel uses a **Hybrid AI Security** model that balances low-latency edge protection with high-accuracy centralized auditing.

## 1. The Hybrid Model

### Fast Path (Edge Node)
- **Agent**: `zentinel-agent-waf` (Rust)
- **Mechanism**: N-gram statistics, Entropy analysis, and Tiny ONNX models.
- **Latency**: < 1ms.
- **Goal**: Block 99% of known attacks and high-entropy anomalies.

### Slow Path (Centralized)
- **Agent**: `zentinel-agent-ai-auditor` (Rust/ONNX)
- **Mechanism**: Deep Semantic Analysis (DistilBERT/Transformers).
- **Latency**: 50ms - 200ms.
- **Goal**: Provide a "Second Opinion" for suspicious requests and verify ModSecurity detections.

## 2. Active Learning Loop (Teacher-Student)

1. **Detection**: A WAF Agent or ModSecurity Agent detects a potential threat.
2. **Auditing**: The Control Plane (`WafAuditWorker`) asynchronously calls the `AI Auditor` for verification.
3. **Validation**:
    - If `ModSecurity` (Teacher) and `AI Auditor` (Student) both agree, the pattern is marked as **Verified True Positive**.
    - If they disagree, it is flagged for **Human Review**.
4. **Reinforcement**: Verified patterns are added to the `ai_knowledge` of the WafPolicy.
5. **Deployment**: Updated patterns are pushed back to all Edge Agents via the `adaptive-patterns` configuration.

## 3. Deployment Configuration

To enable the AI Auditor integration, set the following environment variables in the Control Plane:

```bash
# URL of the shared AI Auditor cluster
export AI_AUDITOR_URL="http://ai-auditor-service:50051"

# Enable background auditing
export ENABLE_WAF_AUDIT=true
```

## 4. Multi-tenant Management
Each project in Zentinel has its own AI Knowledge Base. Even though the Auditor cluster is shared, the learning is isolated per project ID, preventing "cross-contamination" of patterns while allowing for global threat intelligence sharing if enabled.

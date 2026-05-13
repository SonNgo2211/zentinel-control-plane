defmodule ZentinelCp.Ai.AuditorClient do
  @moduledoc """
  Client for communicating with the external zentinel-agent-ai-auditor (Rust).
  """

  require Logger

  @doc """
  Sends a payload to the deep AI auditor for a second opinion.
  """
  def audit(payload, correlation_id \\ nil) do
    # For now, we simulate the gRPC call since we haven't added the grpc dep yet.
    # In a real implementation, this would use a gRPC client.
    
    Logger.info("AI Auditor Client: Requesting deep audit for #{correlation_id || "unknown"}")

    # Mock response logic
    cond do
      String.contains?(payload, "UNION SELECT") ->
        {:ok, %{is_attack: true, confidence: 0.98, reason: "Deep semantic analysis: SQLi detected"}}
      
      String.contains?(payload, "<script>") ->
        {:ok, %{is_attack: true, confidence: 0.95, reason: "Deep semantic analysis: XSS detected"}}

      true ->
        {:ok, %{is_attack: false, confidence: 0.05, reason: "Clean payload"}}
    end
  end
end
